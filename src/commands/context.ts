import {
  AttachmentBuilder,
  MessageFlags,
  type APIEmbed,
  type ActionRowBuilder,
  type ButtonBuilder,
  type ChatInputCommandInteraction
} from "discord.js";
import type { Logger } from "pino";
import type { Severity } from "../core/types.js";
import type { GuildInfo } from "../discord/gateway.js";
import type { SecurityKernel } from "../security/kernel.js";
import type { AccessLevel } from "../security/policy/authorization.js";
import type { PolicyContext } from "../security/policy/policyService.js";
import type { ConfirmationService } from "./confirmations.js";

export interface RouterDependencies {
  kernel: SecurityKernel;
  confirmations: ConfirmationService;
  logger: Logger;
  databaseDriver: "sqlite" | "postgres";
  redisEnabled: boolean;
  backupDir: string;
  startedAt: number;
  integrity: Map<string, { ok: boolean; checked: number; at: number; reason: string | null }>;
}

export interface CommandContext {
  interaction: ChatInputCommandInteraction<"cached">;
  name: string;
  guildId: string;
  userId: string;
  access: AccessLevel;
  policy: PolicyContext;
  guild: GuildInfo;
  deps: RouterDependencies;
}

export type CommandHandler = (context: CommandContext) => Promise<void>;

export interface ReplyPayload {
  content?: string;
  embeds?: APIEmbed[];
  files?: Array<{ name: string; data: Buffer }>;
  components?: ActionRowBuilder<ButtonBuilder>[];
}

export async function respond(context: CommandContext, payload: ReplyPayload): Promise<void> {
  const body = {
    content: payload.content,
    embeds: payload.embeds ?? [],
    files: payload.files?.map((file) => new AttachmentBuilder(file.data, { name: file.name })) ?? [],
    components: payload.components ?? [],
    allowedMentions: { parse: [] as never[] }
  };
  if (context.interaction.deferred || context.interaction.replied) {
    await context.interaction.editReply(body);
  } else {
    await context.interaction.reply({ ...body, flags: MessageFlags.Ephemeral });
  }
}

export async function defer(context: CommandContext): Promise<void> {
  if (!context.interaction.deferred && !context.interaction.replied) await context.interaction.deferReply({ flags: MessageFlags.Ephemeral });
}

export async function recordCommand(context: CommandContext, eventType: string, evidence: Record<string, unknown>, severity: Severity = "info"): Promise<void> {
  await context.deps.kernel.evidence.append({
    guildId: context.guildId,
    eventType,
    severity,
    actorId: context.userId,
    confidence: "high",
    evidence: { command: context.name, access: context.access, ...evidence }
  });
}

export function timestamp(iso: string | number): string {
  const ms = typeof iso === "number" ? iso : Date.parse(iso);
  return `<t:${Math.floor(ms / 1000)}:R>`;
}

export function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
