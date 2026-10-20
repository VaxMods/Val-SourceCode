import crypto from "node:crypto";
import { ActionRowBuilder, ButtonBuilder, ButtonStyle } from "discord.js";
import type { Clock } from "../core/clock.js";
import type { AccessLevel } from "../security/policy/authorization.js";

export interface PendingConfirmation {
  nonce: string;
  guildId: string;
  userId: string;
  action: string;
  requiredAccess: AccessLevel;
  expiresAt: number;
  execute: () => Promise<string>;
}

export type ConfirmationLookup =
  | { status: "ok"; pending: PendingConfirmation; confirmed: boolean }
  | { status: "unknown" }
  | { status: "expired"; pending: PendingConfirmation }
  | { status: "foreign"; pending: PendingConfirmation };

const PREFIX = "vp:confirm:";
const TTL_MS = 60000;

export class ConfirmationService {
  private readonly pending = new Map<string, PendingConfirmation>();

  constructor(private readonly clock: Clock) {}

  create(input: Omit<PendingConfirmation, "nonce" | "expiresAt">): { nonce: string; row: ActionRowBuilder<ButtonBuilder> } {
    this.sweep();
    const nonce = crypto.randomBytes(12).toString("base64url");
    this.pending.set(nonce, { ...input, nonce, expiresAt: this.clock.now() + TTL_MS });
    const row = new ActionRowBuilder<ButtonBuilder>().addComponents(
      new ButtonBuilder().setCustomId(`${PREFIX}${nonce}:yes`).setLabel("Confirm").setStyle(ButtonStyle.Danger),
      new ButtonBuilder().setCustomId(`${PREFIX}${nonce}:no`).setLabel("Cancel").setStyle(ButtonStyle.Secondary)
    );
    return { nonce, row };
  }

  static owns(customId: string): boolean {
    return customId.startsWith(PREFIX);
  }

  consume(customId: string, guildId: string | null, userId: string): ConfirmationLookup {
    const match = /^vp:confirm:([A-Za-z0-9_-]{16}):(yes|no)$/.exec(customId);
    if (!match) return { status: "unknown" };
    const pending = this.pending.get(match[1] as string);
    if (!pending || pending.guildId !== guildId) return { status: "unknown" };
    if (pending.userId !== userId) return { status: "foreign", pending };
    this.pending.delete(pending.nonce);
    if (pending.expiresAt < this.clock.now()) return { status: "expired", pending };
    return { status: "ok", pending, confirmed: match[2] === "yes" };
  }

  sweep(): void {
    const now = this.clock.now();
    for (const [nonce, item] of this.pending) if (item.expiresAt < now - TTL_MS) this.pending.delete(nonce);
  }
}
