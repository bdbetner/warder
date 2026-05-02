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
  accept_degraded: boolean;
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

export interface ReceiptStatus {
  status: string;
  message: string | null;
  path: string | null;
  backend: string | null;
  snapshot_id: string | null;
}

export interface ReceiptAction {
  kind: string;
  label: string;
  command: string;
  command_argv: string[];
  mutates: boolean;
  reason?: string;
}

export interface StructuredReceipt {
  session_id: string;
  status: string;
  exit_code: number | null;
  command: string[];
  protected_zones: string[];
  limitations: string[];
  enforcement: {
    cgroup: ReceiptStatus;
    landlock: ReceiptStatus;
    snapshot: ReceiptStatus;
  };
  file_activity: {
    total_events: number;
    zones: Record<string, number>;
    sources: Record<string, number>;
    attribution: Record<string, number>;
  };
  network_activity: {
    total_events: number;
    destinations: Record<string, number>;
    protocols: Record<string, number>;
    sources: Record<string, number>;
    attribution: Record<string, number>;
  };
  readiness: {
    level: string;
    blocked_reasons: string[];
    degraded_reasons: string[];
  };
  degraded_coverage: {
    total_reasons: number;
  };
  degraded_reasons: string[];
  recovery_actions: ReceiptAction[];
}

export interface HostReadinessSummary {
  level: "strong" | "degraded" | "blocked";
  summary: string;
  blocked_reasons: string[];
  degraded_reasons: string[];
}
