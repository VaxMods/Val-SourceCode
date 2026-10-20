import crypto from "node:crypto";
import type { SectionId } from "../../config/settings.js";
import type { Clock } from "../../core/clock.js";
import type { ChangePlan } from "../../security/policy/settingsService.js";

export type PanelView = "home" | SectionId | "granters" | "whitelist";

export interface PanelNotice {
  ok: boolean;
  text: string;
}

export interface PanelSession {
  id: string;
  guildId: string;
  userId: string;
  view: PanelView;
  returnView: PanelView;
  grantersRoleId: string | null;
  pending: ChangePlan | null;
  notice: PanelNotice | null;
  expiresAt: number;
}

export const PANEL_PREFIX = "vp:p:";
const TTL_MS = 30 * 60000;
const MAX_SESSIONS = 2000;

export class PanelSessions {
  private readonly sessions = new Map<string, PanelSession>();

  constructor(private readonly clock: Clock) {}

  open(guildId: string, userId: string): PanelSession {
    this.sweep();
    for (const [id, session] of this.sessions) if (session.guildId === guildId && session.userId === userId) this.sessions.delete(id);
    if (this.sessions.size >= MAX_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest !== undefined) this.sessions.delete(oldest);
    }
    const session: PanelSession = {
      id: crypto.randomBytes(9).toString("base64url"),
      guildId,
      userId,
      view: "home",
      returnView: "home",
      grantersRoleId: null,
      pending: null,
      notice: null,
      expiresAt: this.clock.now() + TTL_MS
    };
    this.sessions.set(session.id, session);
    return session;
  }

  get(id: string, guildId: string | null, userId: string): PanelSession | null {
    const session = this.sessions.get(id);
    if (!session || session.guildId !== guildId || session.userId !== userId) return null;
    if (session.expiresAt < this.clock.now()) {
      this.sessions.delete(id);
      return null;
    }
    session.expiresAt = this.clock.now() + TTL_MS;
    return session;
  }

  close(id: string): void {
    this.sessions.delete(id);
  }

  sweep(): void {
    const now = this.clock.now();
    for (const [id, session] of this.sessions) if (session.expiresAt < now) this.sessions.delete(id);
  }

  get size(): number {
    return this.sessions.size;
  }
}

export interface ParsedCustomId {
  sessionId: string;
  op: string;
  arg: string | null;
}

export function customId(session: Pick<PanelSession, "id">, op: string, arg?: string): string {
  return `${PANEL_PREFIX}${session.id}:${op}${arg !== undefined ? `:${arg}` : ""}`;
}

export function parseCustomId(value: string): ParsedCustomId | null {
  if (!value.startsWith(PANEL_PREFIX)) return null;
  const match = /^vp:p:([A-Za-z0-9_-]{12}):([a-z]{2,8})(?::([A-Za-z0-9_.:-]{1,80}))?$/.exec(value);
  if (!match) return null;
  return { sessionId: match[1] as string, op: match[2] as string, arg: match[3] ?? null };
}
