import { ACTION_CATEGORIES } from "../core/types.js";
import type { GuildPolicy } from "./schema.js";

export interface SemanticReport {
  errors: string[];
  warnings: string[];
}

const SINGLE_EVENT_CATEGORIES = new Set(["memberPrune", "botAdd", "integrationCreate", "integrationDelete", "commandPermissionUpdate"]);

function intersect(a: readonly string[], b: readonly string[]): string[] {
  const set = new Set(b);
  return a.filter((item) => set.has(item));
}

export function validatePolicySemantics(policy: GuildPolicy): SemanticReport {
  const errors: string[] = [];
  const warnings: string[] = [];
  const raid = policy.antiRaid;
  const honeypot = policy.honeypot;
  const roles = policy.roleProtection;

  const domainOverlap = intersect(policy.antiSpam.links.allowedDomains, policy.antiSpam.links.blockedDomains);
  if (domainOverlap.length > 0) errors.push(`antiSpam.links: domains both allowed and blocked: ${domainOverlap.join(", ")}`);

  if (raid.quarantineRoleId && honeypot.decoyRoleIds.includes(raid.quarantineRoleId)) {
    errors.push("antiRaid.quarantineRoleId must not be a honeypot decoy role");
  }
  if (raid.quarantineRoleId && roles.protectedRoleIds.includes(raid.quarantineRoleId)) {
    errors.push("antiRaid.quarantineRoleId must not be a protected role");
  }
  const decoyProtected = intersect(honeypot.decoyRoleIds, roles.protectedRoleIds);
  if (decoyProtected.length > 0) errors.push(`honeypot.decoyRoleIds overlap with protected roles: ${decoyProtected.join(", ")}`);
  if (policy.alertChannelId && honeypot.decoyChannelIds.includes(policy.alertChannelId)) {
    errors.push("alertChannelId must not be a honeypot decoy channel");
  }
  const decoyStaff = intersect(honeypot.decoyRoleIds, [...policy.staffRoleIds, ...policy.auditorRoleIds]);
  if (decoyStaff.length > 0) errors.push(`honeypot.decoyRoleIds overlap with staff or auditor roles: ${decoyStaff.join(", ")}`);

  if (raid.suspectAction === "kick" && !raid.actOnlyDuringRaid) {
    errors.push("antiRaid.suspectAction=kick requires antiRaid.actOnlyDuringRaid=true; kicking members outside a confirmed raid is refused");
  }
  const weightTotal = Object.values(raid.weights).reduce((sum, value) => sum + value, 0);
  if (weightTotal === 0) errors.push("antiRaid.weights must not all be zero");
  if (!roles.dangerousPermissions.includes("Administrator")) {
    errors.push("roleProtection.dangerousPermissions must include Administrator");
  }

  if (policy.mode === "automatic" && !policy.alertChannelId) {
    warnings.push("mode=automatic without alertChannelId: alerts will only reach the fallback webhook and local files");
  }
  if (policy.securityAdminIds.length === 0) {
    warnings.push("securityAdminIds is empty: only the server owner can administer Val Protection");
  }
  if (raid.suspectAction === "quarantine" && !raid.quarantineRoleId) {
    warnings.push("antiRaid.suspectAction=quarantine but no quarantineRoleId is set: suspects will only be logged");
  }
  if (policy.lockdown.quarantineNewMembers && !raid.quarantineRoleId) {
    warnings.push("lockdown.quarantineNewMembers=true but no quarantineRoleId is set: new members cannot be quarantined during lockdown");
  }
  if (raid.raidScoreThreshold < 30) warnings.push("antiRaid.raidScoreThreshold below 30 will produce false positives");
  if (raid.minJoinsForRaid < 5) warnings.push("antiRaid.minJoinsForRaid below 5 will produce false positives on active servers");
  if (policy.antiSpam.burst.maxMessages < 4) warnings.push("antiSpam.burst.maxMessages below 4 will penalise normal conversation");
  if (policy.lockdown.verificationLevel === "VeryHigh") {
    warnings.push("lockdown.verificationLevel=VeryHigh requires a verified phone number and blocks many legitimate members");
  }
  for (const category of ACTION_CATEGORIES) {
    const threshold = policy.antiNuke.thresholds[category];
    if (threshold.limit === 1 && !SINGLE_EVENT_CATEGORIES.has(category)) {
      warnings.push(`antiNuke.thresholds.${category}.limit=1 triggers on every single action`);
    }
  }
  if (policy.antiNuke.response === "contain" && policy.antiNuke.minConfidenceToContain === "medium") {
    warnings.push("antiNuke.minConfidenceToContain=medium allows containment based on fetched audit logs, not only live audit events");
  }
  if (roles.revokeWhenActorUnknown) {
    warnings.push("roleProtection.revokeWhenActorUnknown=true revokes sensitive roles even when the granter cannot be identified");
  }
  return { errors, warnings };
}
