/**
 * Core types for the MCP server security scoring model.
 * Each CheckResult maps to a numbered section of the MCP Server Security Policy.
 */

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info' | 'unverifiable';

export type SourceType = 'npm' | 'github' | 'registry' | 'remote';

export interface Evidence {
  label: string;
  value?: string;
  url?: string;
}

export interface CheckResult {
  /** Stable check identifier, e.g. "provenance.repo-health" */
  id: string;
  /** Policy section this check verifies, e.g. "§1.2" */
  policyRef: string;
  title: string;
  status: CheckStatus;
  /** One-line human summary of the outcome */
  summary: string;
  evidence: Evidence[];
}

/** A scan target after input resolution, with whatever identifiers could be cross-resolved. */
export interface ScanTarget {
  input: string;
  sourceType: SourceType;
  displayName: string;
  npmPackage?: string;
  github?: { owner: string; repo: string };
  /** Official-registry server name, e.g. "io.github.owner/server" */
  registryName?: string;
  remoteUrl?: string;
}

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** How the tool list was obtained; "none" means capabilities are unverifiable. */
export type ToolSource = 'remote-tools-list' | 'registry-metadata' | 'package-source' | 'none';

export interface ToolSurface {
  source: ToolSource;
  tools: ToolInfo[];
  /** Raw risk keywords found in package source when tools couldn't be enumerated directly */
  sourceRiskHits: RiskHit[];
  /** Remote server demanded auth before listing tools (a §3 pass, a §2 fallback) */
  remoteAuthRequired?: boolean;
}

export interface RiskHit {
  category: RiskCategory;
  pattern: string;
  /** Human label for the matched pattern family */
  label?: string;
  file?: string;
  excerpt?: string;
}

export type RiskCategory =
  | 'process-execution'
  | 'filesystem'
  | 'network-egress'
  | 'credential-access';

export interface CheckContext {
  target: ScanTarget;
  fetch: typeof globalThis.fetch;
  /** GitHub token (public-repo read). Without it, repo checks degrade to unverifiable. */
  githubToken?: string;
  /** Per-request timeout in ms for outbound calls (default 10s) */
  timeoutMs?: number;
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScanReport {
  target: ScanTarget;
  checks: CheckResult[];
  score: number;
  grade: Grade;
  /** SHA-256 over canonicalized tool names+descriptions+input schemas; absent if no tools obtained */
  toolSchemaHash?: string;
  tools?: ToolInfo[];
  toolSource: ToolSource;
  createdAt: string;
}
