import { Client, GatewayIntentBits, Options, Partials } from "discord.js";

export const REQUIRED_INTENTS = [
  GatewayIntentBits.Guilds,
  GatewayIntentBits.GuildMembers,
  GatewayIntentBits.GuildModeration,
  GatewayIntentBits.GuildMessages,
  GatewayIntentBits.MessageContent
] as const;

export function createDiscordClient(): Client {
  return new Client({
    intents: [...REQUIRED_INTENTS],
    partials: [Partials.GuildMember, Partials.Message, Partials.Channel],
    allowedMentions: { parse: [] },
    rest: { timeout: 15000, retries: 3 },
    makeCache: Options.cacheWithLimits({
      ...Options.DefaultMakeCacheSettings,
      MessageManager: 50,
      ReactionManager: 0,
      ReactionUserManager: 0,
      GuildEmojiManager: 0,
      GuildStickerManager: 0,
      PresenceManager: 0,
      VoiceStateManager: 0,
      GuildScheduledEventManager: 0,
      StageInstanceManager: 0,
      AutoModerationRuleManager: 0
    }),
    sweepers: {
      ...Options.DefaultSweeperSettings,
      messages: { interval: 300, lifetime: 900 }
    }
  });
}
