import type { GuildInfo, MemberInfo, RoleInfo } from "../discord/gateway.js";
import { ADMINISTRATOR, has } from "../discord/permissions.js";

export interface Capability {
  ok: boolean;
  reason?: string;
}

export function canManageRole(guild: GuildInfo, role: RoleInfo): Capability {
  if (!has(guild.botPermissions, "ManageRoles")) return { ok: false, reason: "Val Protection lacks the Manage Roles permission" };
  if (role.isEveryone) return { ok: false, reason: "@everyone cannot be assigned or removed" };
  if (role.managed) return { ok: false, reason: "managed integration roles cannot be assigned or removed" };
  if (role.position >= guild.botHighestRolePosition) {
    return { ok: false, reason: `role "${role.name}" is at or above Val Protection's highest role` };
  }
  return { ok: true };
}

export function canEditRolePermissions(guild: GuildInfo, role: RoleInfo, desired: bigint): Capability {
  if (!has(guild.botPermissions, "ManageRoles")) return { ok: false, reason: "Val Protection lacks the Manage Roles permission" };
  if (role.position >= guild.botHighestRolePosition) {
    return { ok: false, reason: `role "${role.name}" is at or above Val Protection's highest role` };
  }
  const isAdmin = (guild.botPermissions & ADMINISTRATOR) === ADMINISTRATOR;
  const changed = role.permissions ^ desired;
  if (!isAdmin && (changed & ~guild.botPermissions) !== 0n) {
    return { ok: false, reason: "Discord only lets a bot add or remove permissions it holds itself" };
  }
  return { ok: true };
}

export function canModerateMember(guild: GuildInfo, member: MemberInfo): Capability {
  if (member.id === guild.botUserId) return { ok: false, reason: "Val Protection never acts on itself" };
  if (member.isOwner) return { ok: false, reason: "Discord does not allow any bot to restrict the server owner" };
  if (member.highestRolePosition >= guild.botHighestRolePosition) {
    return { ok: false, reason: "member's highest role is at or above Val Protection's highest role" };
  }
  return { ok: true };
}

export function canTimeout(guild: GuildInfo, member: MemberInfo): Capability {
  const base = canModerateMember(guild, member);
  if (!base.ok) return base;
  if (!has(guild.botPermissions, "ModerateMembers")) return { ok: false, reason: "Val Protection lacks the Moderate Members permission" };
  if ((member.permissions & ADMINISTRATOR) === ADMINISTRATOR) return { ok: false, reason: "Discord does not allow timing out administrators" };
  return { ok: true };
}

export function canKick(guild: GuildInfo, member: MemberInfo): Capability {
  const base = canModerateMember(guild, member);
  if (!base.ok) return base;
  if (!has(guild.botPermissions, "KickMembers")) return { ok: false, reason: "Val Protection lacks the Kick Members permission" };
  return { ok: true };
}
