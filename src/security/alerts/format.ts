import type { APIEmbed, APIEmbedField } from "discord.js";
import { redactString } from "../../core/redact.js";
import type { ActionRecord, Severity } from "../../core/types.js";

export const SEVERITY_COLOR: Record<Severity, number> = {
  info: 0x95a5a6,
  low: 0x3498db,
  medium: 0xf1c40f,
  high: 0xe67e22,
  critical: 0xe74c3c
};

export function sanitize(value: string, max = 1000): string {
  const cleaned = redactString(value)
    .replace(/@(everyone|here)/gi, "@\u200b$1")
    .replace(/`/g, "'")
    .replace(/\u0000/g, "");
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

export function userRef(id: string | null | undefined): string {
  return id ? `<@${id}> (${id})` : "unknown";
}

export function roleRef(id: string | null | undefined): string {
  return id ? `<@&${id}> (${id})` : "unknown";
}

export function channelRef(id: string | null | undefined): string {
  return id ? `<#${id}> (${id})` : "unknown";
}

export interface AlertContent {
  severity: Severity;
  title: string;
  description: string;
  fields?: APIEmbedField[];
  incidentId?: string | null;
  timestamp: number;
}

export function buildEmbed(content: AlertContent): APIEmbed {
  const fields = (content.fields ?? []).slice(0, 24).map((field) => ({
    name: sanitize(field.name, 256),
    value: sanitize(field.value || "-", 1024),
    inline: field.inline ?? false
  }));
  return {
    title: sanitize(`[${content.severity.toUpperCase()}] ${content.title}`, 256),
    description: sanitize(content.description, 3500),
    color: SEVERITY_COLOR[content.severity],
    fields,
    footer: { text: content.incidentId ? `Val Protection • ${content.incidentId}` : "Val Protection" },
    timestamp: new Date(content.timestamp).toISOString()
  };
}

export function describeActions(actions: readonly ActionRecord[]): string {
  if (actions.length === 0) return "No automatic action was taken.";
  return actions
    .map((record) => {
      const state = record.outcome.skipped ? "SKIPPED" : record.outcome.ok ? "DONE" : "FAILED";
      const detail = record.outcome.error ?? record.outcome.detail ?? "";
      return `${state} ${record.action}${record.target ? ` → ${record.target}` : ""}: ${record.rationale}${detail ? ` (${detail})` : ""}`;
    })
    .join("\n");
}
