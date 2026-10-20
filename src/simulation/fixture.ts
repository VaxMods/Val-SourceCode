import { ChannelType } from "discord.js";
import { REQUIRED_BOT_PERMISSIONS, bitsOf } from "../discord/permissions.js";
import { InMemoryGateway } from "./inMemoryGateway.js";

export const FIXTURE_IDS = {
  guildId: "100000000000000001",
  ownerId: "200000000000000001",
  botId: "200000000000000002",
  securityAdminId: "200000000000000003",
  rogueId: "200000000000000004",
  roles: {
    botRole: "400000000000000001",
    admin: "400000000000000002",
    roleManager: "400000000000000003",
    moderator: "400000000000000004",
    channelManager: "400000000000000005",
    decoy: "400000000000000006",
    quarantine: "400000000000000007",
    member: "400000000000000008"
  },
  channels: {
    staffCategory: "500000000000000001",
    alerts: "500000000000000002",
    general: "500000000000000003",
    announcements: "500000000000000004",
    rules: "500000000000000005"
  }
} as const;

export type FixtureIds = typeof FIXTURE_IDS;

export function buildFixture(now: () => number = Date.now): { gateway: InMemoryGateway; ids: FixtureIds; memberIds: string[] } {
  const ids = FIXTURE_IDS;
  const gateway = new InMemoryGateway({ guildId: ids.guildId, name: "Simulation Server", ownerId: ids.ownerId, botUserId: ids.botId }, now);
  gateway.setRolePermissionsDirect(ids.guildId, bitsOf(["ViewChannel", "SendMessages", "ReadMessageHistory", "EmbedLinks", "AttachFiles", "AddReactions"]));
  gateway.addRole({ id: ids.roles.botRole, name: "Val Protection", permissions: bitsOf(REQUIRED_BOT_PERMISSIONS), position: 20, managed: true, botId: ids.botId });
  gateway.addRole({ id: ids.roles.admin, name: "Admin", permissions: bitsOf(["Administrator"]), position: 15 });
  gateway.addRole({ id: ids.roles.roleManager, name: "Role Manager", permissions: bitsOf(["ManageRoles"]), position: 12 });
  gateway.addRole({ id: ids.roles.moderator, name: "Moderator", permissions: bitsOf(["BanMembers", "KickMembers", "ModerateMembers", "ManageMessages"]), position: 11 });
  gateway.addRole({ id: ids.roles.channelManager, name: "Channel Manager", permissions: bitsOf(["ManageChannels", "ManageWebhooks"]), position: 10 });
  gateway.addRole({ id: ids.roles.decoy, name: "Admin Applicant", permissions: 0n, position: 5 });
  gateway.addRole({ id: ids.roles.quarantine, name: "Quarantine", permissions: 0n, position: 3 });
  gateway.addRole({ id: ids.roles.member, name: "Member", permissions: 0n, position: 2 });
  gateway.addMember({ id: ids.ownerId, username: "owner" });
  gateway.addMember({ id: ids.botId, username: "Val Protection", isBot: true, roleIds: [ids.roles.botRole] });
  gateway.addMember({ id: ids.securityAdminId, username: "security.admin", roleIds: [ids.roles.admin] });
  gateway.addMember({ id: ids.rogueId, username: "rogue.moderator", roleIds: [ids.roles.roleManager, ids.roles.moderator, ids.roles.channelManager] });
  const memberIds: string[] = [];
  for (let index = 0; index < 12; index += 1) {
    const id = (300000000000000001n + BigInt(index)).toString();
    gateway.addMember({ id, username: `member_${["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima"][index]}`, roleIds: [ids.roles.member] });
    memberIds.push(id);
  }
  gateway.addChannel({ id: ids.channels.staffCategory, name: "staff", type: ChannelType.GuildCategory, position: 0 });
  gateway.addChannel({ id: ids.channels.alerts, name: "security-alerts", parentId: ids.channels.staffCategory, position: 1 });
  gateway.addChannel({ id: ids.channels.general, name: "general", position: 2 });
  gateway.addChannel({ id: ids.channels.announcements, name: "announcements", position: 3 });
  gateway.addChannel({ id: ids.channels.rules, name: "rules", position: 4 });
  return { gateway, ids, memberIds };
}

export function fixturePolicy(ids: FixtureIds = FIXTURE_IDS): Record<string, unknown> {
  return {
    mode: "automatic",
    alertChannelId: ids.channels.alerts,
    securityAdminIds: [ids.securityAdminId],
    staffRoleIds: [ids.roles.moderator],
    antiRaid: { quarantineRoleId: ids.roles.quarantine },
    honeypot: { decoyRoleIds: [ids.roles.decoy] }
  };
}
