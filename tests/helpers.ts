import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AuditLogEvent } from "discord.js";
import type { IncidentRecord } from "../src/database/repositories/incidentRepository.js";
import { createSimulation, type Simulation, type SimulationOptions } from "../src/simulation/harness.js";

export { AuditLogEvent };

export async function simulate(options: SimulationOptions = {}): Promise<Simulation> {
  return createSimulation(options);
}

export async function incidents(sim: Simulation): Promise<IncidentRecord[]> {
  return (await sim.repos.incidents.recent(sim.ids.guildId, 100)).reverse();
}

export async function incidentOfType(sim: Simulation, type: string): Promise<IncidentRecord | undefined> {
  return (await incidents(sim)).find((item) => item.type === type);
}

export function methods(sim: Simulation): string[] {
  return sim.gateway.calls.map((call) => call.method);
}

export async function memberRoles(sim: Simulation, memberId: string): Promise<string[]> {
  return (await sim.gateway.getMember(sim.ids.guildId, memberId))?.roleIds ?? [];
}

export function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vp-${prefix}-`));
}

export async function grantAudit(sim: Simulation, executorId: string | null, targetId: string, roleId: string, roleName = "role"): Promise<void> {
  sim.gateway.grantRoleDirect(targetId, roleId);
  await sim.audit({
    actionType: AuditLogEvent.MemberRoleUpdate,
    executorId,
    targetId,
    changes: [{ key: "$add", old: null, new: [{ id: roleId, name: roleName }] }]
  });
}

export function fakeBotToken(): string {
  return ["MTIzNDU2Nzg5MDEyMzQ1Njc4OTA", "AbCdEf", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"].join(".");
}

export function fakeWebhookUrl(id: string, secret: string, host = "discord.com/api"): string {
  return ["https:/", host, "webhooks", id, secret].join("/");
}

export function fakeConnectionString(): string {
  return ["postgres://", "user", ":", "pass", "@db:5432/x"].join("");
}
