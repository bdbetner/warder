export type ProtectionAccess = "read-write" | "write-only";
export type ProtectionKind = "sensitive-user" | "vital-system";

export interface RecommendedProtection {
  id: string;
  label: string;
  path: string;
  kind: ProtectionKind;
  access: ProtectionAccess;
  reason: string;
  exists: boolean;
  enabled_by_default: boolean;
}

export interface ProtectedPathSelection extends RecommendedProtection {
  selected: boolean;
  readProtected: boolean;
  writeProtected: boolean;
  snapshotProtected: boolean;
}

export interface AppPolicyState {
  setupComplete: boolean;
  selectedProfileId: string;
  agentCommand: string;
  networkJournal: boolean;
  requireEnforcement: boolean;
  configPath: string;
  dbPath: string;
  protectedPaths: ProtectedPathSelection[];
}

export interface GuiAgentConfig {
  id: string;
  label: string;
  command: string;
  profile: string | null;
}

export interface GuiProtectedPath {
  id: string;
  label: string;
  path: string;
  read_protected: boolean;
  write_protected: boolean;
  snapshot: boolean;
}

export interface ProfileProtectedPathTemplate {
  label: string;
  path: string;
  resolved_path: string;
  read: boolean;
  write: boolean;
}

export interface ProfileSetupTemplate {
  recommended_protected_paths: ProfileProtectedPathTemplate[];
  writable_roots: string[];
  network_journal: boolean;
  snapshot: "best-effort" | "disabled";
}

export interface ProfileTemplateCatalogEntry {
  id: string;
  declared_command: string;
  summary: string;
  preflight: string;
  effect: string;
  template: ProfileSetupTemplate;
}

export interface GuiConfigDraft {
  agent: GuiAgentConfig;
  protected_paths: GuiProtectedPath[];
  network_journal: boolean;
}

export interface LaunchRequest {
  config_path: string;
  db_path: string;
  agent_id: string;
  command: string[];
  require_enforcement: boolean;
}

export interface DesktopPaths {
  project_root: string;
  config_path: string;
  db_path: string;
}

export interface LaunchSessionResult {
  session_id: string;
  exit_code: number | null;
  validation_warnings: string[];
  receipt: string;
}

export interface RecentSessionSummary {
  id: string;
  status: string;
  command: string;
  started_at_unix_seconds: number;
  file_journal_events: number;
  network_journal_events: number;
  degraded_reasons: number;
}

export interface HostReadinessSummary {
  level: "strong" | "degraded" | "blocked";
  summary: string;
  blocked_reasons: string[];
  degraded_reasons: string[];
}
