import type { ActionRecord } from "../../core/types.js";
import type { DiscordGateway } from "../../discord/gateway.js";
import { ADMINISTRATOR, bitsOf, namesOf, type PermissionName } from "../../discord/permissions.js";
import { canKick, canManageRole } from "../hierarchy.js";

export class ContainmentResponder {
  constructor(private readonly gateway: DiscordGateway) {}

  async stripPermissionRoles(guildId: string, actorId: string, permissions: readonly PermissionName[], reason: string): Promise<ActionRecord[]> {
    const action = "remove-roles-granting-abused-permissions";
    const guild = await this.gateway.getGuild(guildId);
    if (!guild) return [skip(action, actorId, "guild unavailable")];
    const member = await this.gateway.getMember(guildId, actorId);
    if (!member) return [skip(action, actorId, "actor is no longer a member of the server")];
    if (member.isOwner) return [skip(action, actorId, "Discord does not allow any bot to restrict the server owner")];
    if (member.id === guild.botUserId) return [skip(action, actorId, "Val Protection never acts on itself")];
    const mask = bitsOf(permissions);
    const roles = await this.gateway.listRoles(guildId);
    const held = roles.filter((role) => member.roleIds.includes(role.id));
    const relevant = held.filter((role) => (role.permissions & mask) !== 0n || (role.permissions & ADMINISTRATOR) === ADMINISTRATOR);
    if (relevant.length === 0) {
      return [skip(action, actorId, "no role held by the actor grants the abused permissions (they may come from @everyone or channel overwrites)")];
    }
    const removable = relevant.filter((role) => canManageRole(guild, role).ok);
    const blocked = relevant.filter((role) => !canManageRole(guild, role).ok);
    const records: ActionRecord[] = [];
    if (removable.length > 0) {
      const outcome = await this.gateway.removeMemberRoles(
        guildId,
        actorId,
        removable.map((role) => role.id),
        reason
      );
      records.push({
        action,
        target: actorId,
        rationale: `Removed only the roles granting ${permissions.join("/")}: ${removable.map((role) => role.name).join(", ")}`,
        outcome
      });
    }
    for (const role of blocked) {
      records.push(skip(action, actorId, `cannot remove "${role.name}": ${canManageRole(guild, role).reason}. Manual intervention required.`));
    }
    const everyone = roles.find((role) => role.isEveryone);
    if (everyone && (everyone.permissions & mask) !== 0n) {
      records.push(skip(action, actorId, `@everyone itself grants ${namesOf(everyone.permissions & mask).join(", ")}; fix the @everyone role manually`));
    }
    return records;
  }

  async kickBot(guildId: string, botId: string, reason: string): Promise<ActionRecord> {
    const action = "kick-bot";
    const guild = await this.gateway.getGuild(guildId);
    const member = await this.gateway.getMember(guildId, botId);
    if (!guild || !member) return skip(action, botId, "bot is no longer in the server");
    const capability = canKick(guild, member);
    if (!capability.ok) return skip(action, botId, capability.reason ?? "cannot kick");
    const outcome = await this.gateway.kickMember(guildId, botId, reason);
    return { action, target: botId, rationale: reason, outcome };
  }
}

export function skip(action: string, target: string | null, reason: string): ActionRecord {
  return { action, target, rationale: reason, outcome: { ok: false, skipped: true, action, detail: reason } };
}
