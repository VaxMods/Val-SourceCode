import type { Kysely } from "kysely";
import type { Database } from "../types.js";
import { BotRegistryRepository } from "./botRegistryRepository.js";
import { EventRepository } from "./eventRepository.js";
import { IncidentRepository } from "./incidentRepository.js";
import { LockdownRepository } from "./lockdownRepository.js";
import { ProtectedRoleRepository } from "./protectedRoleRepository.js";
import { SettingsRepository } from "./settingsRepository.js";
import { SnapshotRepository } from "./snapshotRepository.js";
import { WhitelistRepository } from "./whitelistRepository.js";

export interface Repositories {
  settings: SettingsRepository;
  whitelist: WhitelistRepository;
  protectedRoles: ProtectedRoleRepository;
  incidents: IncidentRepository;
  events: EventRepository;
  lockdowns: LockdownRepository;
  bots: BotRegistryRepository;
  snapshots: SnapshotRepository;
}

export function createRepositories(db: Kysely<Database>): Repositories {
  return {
    settings: new SettingsRepository(db),
    whitelist: new WhitelistRepository(db),
    protectedRoles: new ProtectedRoleRepository(db),
    incidents: new IncidentRepository(db),
    events: new EventRepository(db),
    lockdowns: new LockdownRepository(db),
    bots: new BotRegistryRepository(db),
    snapshots: new SnapshotRepository(db)
  };
}
