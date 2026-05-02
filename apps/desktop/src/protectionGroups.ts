import type { ProtectedPathSelection } from "./types";

export const PROTECTION_GROUPS = [
  "Credentials and secrets",
  "Agent app state",
  "Project and user folders",
  "System safeguards",
] as const;

export type ProtectionGroup = (typeof PROTECTION_GROUPS)[number];

export function protectionGroupForPath(path: ProtectedPathSelection): ProtectionGroup {
  const value = `${path.label} ${path.path}`.toLowerCase();
  if (path.kind === "vital-system") {
    return "System safeguards";
  }
  if (
    value.includes("ssh") ||
    value.includes("gpg") ||
    value.includes("github") ||
    value.includes("aws") ||
    value.includes("cloud") ||
    value.includes("kube") ||
    value.includes("secret") ||
    value.includes("token") ||
    value.includes("credential")
  ) {
    return "Credentials and secrets";
  }
  if (
    value.includes("codex") ||
    value.includes("claude") ||
    value.includes("openclaw") ||
    value.includes("goose")
  ) {
    return "Agent app state";
  }
  return "Project and user folders";
}

export function protectionGroupCounts(paths: ProtectedPathSelection[]) {
  return paths.reduce<Partial<Record<ProtectionGroup, number>>>((counts, path) => {
    const group = protectionGroupForPath(path);
    counts[group] = (counts[group] ?? 0) + 1;
    return counts;
  }, {});
}

export function groupProtectedPaths(paths: ProtectedPathSelection[]) {
  const groups = new Map<ProtectionGroup, ProtectedPathSelection[]>();
  for (const path of paths) {
    const group = protectionGroupForPath(path);
    groups.set(group, [...(groups.get(group) ?? []), path]);
  }
  return Array.from(groups.entries()).sort(
    ([left], [right]) => PROTECTION_GROUPS.indexOf(left) - PROTECTION_GROUPS.indexOf(right),
  );
}
