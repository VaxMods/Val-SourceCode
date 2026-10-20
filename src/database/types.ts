export interface GuildSettingsTable {
  guild_id: string;
  overrides_json: string;
  revision: number;
  updated_at: string;
  updated_by: string;
}

export interface WhitelistTable {
  id: string;
  guild_id: string;
  subject_id: string;
  subject_type: string;
  scopes_json: string;
  reason: string;
  created_by: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

export interface ProtectedRoleTable {
  guild_id: string;
  role_id: string;
  allowed_granter_ids_json: string;
  allowed_granter_role_ids_json: string;
  created_by: string;
  created_at: string;
}

export interface IncidentTable {
  id: string;
  guild_id: string;
  type: string;
  severity: string;
  status: string;
  actor_id: string | null;
  target_id: string | null;
  confidence: string;
  summary: string;
  details_json: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityEventTable {
  guild_id: string;
  seq: number;
  occurred_at: string;
  event_type: string;
  severity: string;
  actor_id: string | null;
  target_id: string | null;
  confidence: string;
  action: string | null;
  action_result: string | null;
  evidence_json: string;
  error: string | null;
  incident_id: string | null;
  prev_hash: string;
  hash: string;
}

export interface LogAnchorTable {
  guild_id: string;
  seq: number;
  hash: string;
  purged_at: string;
  purged_count: number;
}

export interface LockdownTable {
  guild_id: string;
  active: number;
  reason: string;
  triggered_by: string;
  started_at: string;
  expires_at: string;
  ended_at: string | null;
  ended_by: string | null;
  previous_state_json: string;
}

export interface BotRegistryTable {
  guild_id: string;
  bot_id: string;
  status: string;
  added_by: string | null;
  added_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  risk_json: string;
}

export interface SnapshotTable {
  id: string;
  guild_id: string;
  created_at: string;
  data_json: string;
  hash: string;
  role_count: number;
  channel_count: number;
}

export interface Database {
  guild_settings: GuildSettingsTable;
  whitelist_entries: WhitelistTable;
  protected_roles: ProtectedRoleTable;
  incidents: IncidentTable;
  security_events: SecurityEventTable;
  log_anchors: LogAnchorTable;
  lockdowns: LockdownTable;
  bot_registry: BotRegistryTable;
  guild_snapshots: SnapshotTable;
}
