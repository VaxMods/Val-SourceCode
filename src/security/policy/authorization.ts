import type { WhitelistScope } from "../../core/types.js";
import type { GuildInfo, MemberInfo } from "../../discord/gateway.js";
import type { PolicyContext, ProtectedRoleRule } from "./policyService.js";

export type AccessLevel = "none" | "auditor" | "securityAdmin" | "owner";

const LEVEL_RANK: Record<AccessLevel, number> = { none: 0, auditor: 1, securityAdmin: 2, owner: 3 };

export function hasAccess(level: AccessLevel, required: AccessLevel): boolean {
  return LEVEL_RANK[level] >= LEVEL_RANK[required];
}

export function resolveAccess(context: PolicyContext, guild: GuildInfo, userId: string, memberRoleIds: readonly string[]): AccessLevel {
  if (userId === guild.ownerId) return "owner";
  if (context.policy.securityAdminIds.includes(userId)) return "securityAdmin";
  if (memberRoleIds.some((roleId) => context.policy.auditorRoleIds.includes(roleId))) return "auditor";
  return "none";
}

export interface TrustDecision {
  trusted: boolean;
  reason: string;
}

export function trustActor(context: PolicyContext, guild: GuildInfo, actorId: string | null, scope: WhitelistScope): TrustDecision {
  if (!actorId) return { trusted: false, reason: "actor could not be identified" };
  if (actorId === guild.botUserId) return { trusted: true, reason: "action performed by Val Protection" };
  if (actorId === guild.ownerId) return { trusted: true, reason: "server owner" };
  if (context.policy.securityAdminIds.includes(actorId)) return { trusted: true, reason: "configured security administrator" };
  const entry = context.whitelist.find((item) => item.subjectId === actorId && (item.scopes.includes("all") || item.scopes.includes(scope)));
  if (entry) return { trusted: true, reason: `whitelisted for ${entry.scopes.join(", ")} by ${entry.createdBy}` };
  return { trusted: false, reason: "actor is not owner, security administrator or whitelisted for this scope" };
}

export interface GrantAuthorization {
  status: "authorized" | "unauthorized" | "unknown";
  reason: string;
}

export function authorizeRoleGrant(
  context: PolicyContext,
  guild: GuildInfo,
  actorId: string | null,
  actor: MemberInfo | null,
  rule: ProtectedRoleRule | undefined,
  lockdownActive: boolean
): GrantAuthorization {
  if (!actorId) return { status: "unknown", reason: "the audit log does not identify who granted the role" };
  if (actorId === guild.botUserId) return { status: "authorized", reason: "granted by Val Protection" };
  if (actorId === guild.ownerId) return { status: "authorized", reason: "granted by the server owner" };
  if (context.policy.securityAdminIds.includes(actorId)) return { status: "authorized", reason: "granted by a configured security administrator" };
  if (lockdownActive && context.policy.lockdown.restrictProtectedRoleGrants) {
    return { status: "unauthorized", reason: "lockdown restricts sensitive role grants to the owner and security administrators" };
  }
  if (context.policy.roleProtection.authorizedGranterIds.includes(actorId)) {
    return { status: "authorized", reason: "actor is listed in roleProtection.authorizedGranterIds" };
  }
  if (rule?.allowedGranterIds.includes(actorId)) return { status: "authorized", reason: "actor is an allowed granter for this protected role" };
  if (rule && actor && actor.roleIds.some((roleId) => rule.allowedGranterRoleIds.includes(roleId))) {
    return { status: "authorized", reason: "actor holds a role allowed to grant this protected role" };
  }
  const entry = context.whitelist.find((item) => item.subjectId === actorId && (item.scopes.includes("all") || item.scopes.includes("roles")));
  if (entry) return { status: "authorized", reason: `actor is whitelisted for roles by ${entry.createdBy}` };
  return { status: "unauthorized", reason: "the security policy does not allow this actor to grant this role" };
}
