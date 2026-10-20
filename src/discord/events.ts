import { Events, PermissionFlagsBits, type Client } from "discord.js";
import type { Logger } from "pino";
import type { InFlightTracker } from "../app/inFlight.js";
import type { CommandRouter } from "../commands/router.js";
import { errorMessage } from "../core/errors.js";
import type { HealthMonitor } from "../core/health.js";
import type { SecurityKernel } from "../security/kernel.js";
import { normalizeAuditEntry } from "./auditEvent.js";

export interface EventWiring {
  client: Client;
  kernel: SecurityKernel;
  router: CommandRouter;
  tracker: InFlightTracker;
  health: HealthMonitor;
  logger: Logger;
  onGuildAvailable(guildId: string): Promise<void>;
}

export function registerEventHandlers(wiring: EventWiring): void {
  const { client, kernel, router, tracker, health, logger } = wiring;
  const gateway = kernel.deps.gateway;
  const run = (event: string, guildId: string | null, task: () => Promise<unknown>): void => {
    if (guildId && !kernel.policies.isGuildAllowed(guildId)) return;
    tracker.track(
      task().catch((error: unknown) => {
        logger.error({ err: errorMessage(error), event, guildId }, "Event handler failed");
      })
    );
  };

  client.on(Events.GuildAuditLogEntryCreate, (entry, guild) => {
    run("guildAuditLogEntryCreate", guild.id, () =>
      kernel.dispatcher.dispatch(
        normalizeAuditEntry(
          {
            id: entry.id,
            action: entry.action,
            executorId: entry.executorId,
            targetId: entry.targetId,
            reason: entry.reason,
            changes: entry.changes,
            extra: entry.extra,
            createdTimestamp: entry.createdTimestamp
          },
          guild.id,
          "gateway"
        )
      )
    );
  });

  client.on(Events.GuildMemberAdd, (member) => {
    run("guildMemberAdd", member.guild.id, async () => {
      if (member.user.bot) {
        await kernel.botGuard.onBotJoined(member.guild.id, member.id);
        return;
      }
      const info = await gateway.getMember(member.guild.id, member.id);
      if (info) await kernel.antiRaid.onMemberJoin(info);
    });
  });

  client.on(Events.GuildMemberUpdate, (oldMember, newMember) => {
    if (oldMember.partial) return;
    const added = [...newMember.roles.cache.keys()].filter((id) => !oldMember.roles.cache.has(id));
    const removed = [...oldMember.roles.cache.keys()].filter((id) => !newMember.roles.cache.has(id));
    run("guildMemberUpdate", newMember.guild.id, async () => {
      if (newMember.id === client.user?.id) {
        await kernel.tamper.onBotRolesRemoved(newMember.guild.id, removed);
        return;
      }
      if (added.length > 0) await kernel.roleGuard.onMemberRolesAdded(newMember.guild.id, newMember.id, added);
    });
  });

  client.on(Events.GuildRoleUpdate, (oldRole, newRole) => {
    const guildId = newRole.guild.id;
    const isBotRole = newRole.tags?.botId === client.user?.id || newRole.guild.members.me?.roles.highest.id === newRole.id;
    const permissionsChanged = oldRole.permissions.bitfield !== newRole.permissions.bitfield;
    const moved = oldRole.position !== newRole.position;
    if (!isBotRole && !moved) return;
    run("guildRoleUpdate", guildId, async () => {
      const info = await gateway.getRole(guildId, newRole.id);
      if (!info) return;
      if (isBotRole && (permissionsChanged || moved)) await kernel.tamper.onBotRoleChanged(guildId, info, oldRole.permissions.bitfield, oldRole.position);
      if (moved && !isBotRole) await kernel.roleGuard.onRolePositionChanged(guildId, info, oldRole.position);
    });
  });

  client.on(Events.MessageCreate, (message) => {
    if (!message.inGuild() || message.author.bot || message.webhookId || message.system) return;
    const guildId = message.guildId;
    run("messageCreate", guildId, async () => {
      const context = await kernel.policies.context(guildId);
      const member = message.member;
      const roleIds = member ? [...member.roles.cache.keys()] : [];
      const permissions = member?.permissions.bitfield ?? 0n;
      const isStaff = roleIds.some((id) => context.policy.staffRoleIds.includes(id)) || (permissions & PermissionFlagsBits.ManageMessages) !== 0n;
      if (context.policy.honeypot.enabled) {
        if (context.policy.honeypot.decoyChannelIds.includes(message.channelId)) {
          await kernel.honeypot.onDecoyChannelMessage(guildId, message.channelId, message.author.id, isStaff);
        }
        const pattern = kernel.honeypot.matchForbiddenCommand(context, message.content);
        if (pattern && !isStaff) {
          await kernel.honeypot.signal({ guildId, userId: message.author.id, kind: "forbidden-command", context: { pattern, channelId: message.channelId, messageId: message.id } });
        }
      }
      await kernel.antiSpam.onMessage(
        {
          id: message.id,
          guildId,
          channelId: message.channelId,
          authorId: message.author.id,
          content: message.content,
          mentionCount: message.mentions.users.size + message.mentions.roles.size,
          canMentionEveryone: (permissions & PermissionFlagsBits.MentionEveryone) !== 0n,
          createdAt: message.createdTimestamp
        },
        { roleIds, permissions, isOwner: message.author.id === message.guild.ownerId }
      );
    });
  });

  client.on(Events.MessageBulkDelete, (messages, channel) => {
    run("messageBulkDelete", channel.guild.id, () => kernel.tamper.onBulkDeleteWithoutAudit(channel.guild.id, channel.id, messages.size));
  });

  client.on(Events.ThreadCreate, (thread, newlyCreated) => {
    if (!newlyCreated || !thread.ownerId) return;
    const ownerId = thread.ownerId;
    run("threadCreate", thread.guild.id, async () => {
      const owner = await gateway.getMember(thread.guild.id, ownerId);
      if (!owner || owner.isBot) return;
      await kernel.antiSpam.onThreadCreated(thread.guild.id, thread.id, ownerId, { roleIds: owner.roleIds, permissions: owner.permissions, isOwner: owner.isOwner }, thread.parentId);
    });
  });

  client.on(Events.GuildBanAdd, (ban) => {
    run("guildBanAdd", ban.guild.id, () => kernel.antiNuke.onUnattributedAction(ban.guild.id, "memberBan", ban.user.id));
  });

  client.on(Events.GuildCreate, (guild) => {
    if (!kernel.policies.isGuildAllowed(guild.id)) {
      logger.warn({ guildId: guild.id, name: guild.name }, "Joined a guild that is not in allowedGuildIds; it is ignored");
      return;
    }
    run("guildCreate", guild.id, () => wiring.onGuildAvailable(guild.id));
  });

  client.on(Events.GuildDelete, (guild) => {
    if (!guild.available) {
      logger.warn({ guildId: guild.id }, "Guild became unavailable (Discord outage)");
      return;
    }
    run("guildDelete", guild.id, () => kernel.tamper.onBotRemoved(guild.id, guild.name ?? guild.id));
  });

  client.on(Events.InteractionCreate, (interaction) => {
    run("interactionCreate", interaction.guildId, () => router.handle(interaction));
  });

  client.on(Events.ShardDisconnect, (event, shardId) => {
    health.degraded(`gateway:${shardId}`, `disconnected (code ${event.code})`);
    logger.warn({ shardId, code: event.code }, "Gateway disconnected");
  });
  client.on(Events.ShardReconnecting, (shardId) => logger.warn({ shardId }, "Gateway reconnecting"));
  client.on(Events.ShardResume, (shardId, replayed) => {
    health.healthy(`gateway:${shardId}`);
    logger.info({ shardId, replayed }, "Gateway resumed");
  });
  client.on(Events.ShardReady, (shardId) => {
    health.healthy(`gateway:${shardId}`);
    logger.info({ shardId }, "Shard ready");
  });
  client.on(Events.ShardError, (error, shardId) => logger.error({ err: errorMessage(error), shardId }, "Shard error"));
  client.on(Events.Error, (error) => logger.error({ err: errorMessage(error) }, "Discord client error"));
  client.on(Events.Warn, (message) => logger.warn({ message }, "Discord client warning"));
  client.rest.on("rateLimited", (info) => logger.warn({ route: info.route, timeToReset: info.timeToReset, global: info.global }, "Discord rate limit reached"));
}
