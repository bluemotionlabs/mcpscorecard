# The MCP Server Security Policy

**Version 0.1 (skeleton draft — structure and section numbering are stable; prose is a working draft pending the author's pass)**

A scored, tool-verifiable acceptance standard for evaluating a third-party Model Context Protocol (MCP) server *before* connecting it to an agent.

## Why this document exists

Excellent general guidance on MCP security already exists — the official specification's security best practices, the OWASP MCP Top 10, NSA's *MCP: Security Design Considerations for AI-Driven Automation* (May 2026), Anthropic's *Zero Trust for AI Agents* (May 2026), and the Cloud Security Alliance's agentic security work. What none of them provide is an **acceptance standard**: a concrete, scored answer to the question every team faces at the moment of adoption — *should we connect this specific server?*

This policy fills that gap. It is:

- **Scored.** Each section rolls up into a 0–100 score and A–F grade, so "how risky is this server?" has a legible answer, not a reading assignment.
- **Tool-verifiable.** Every requirement marked *Verified by* is checked automatically by the companion open-source rubric ([`@mcpscorecard/checks`](https://github.com/bluemotionlabs/mcpscorecard)), which implements this policy check-for-check. Requirements marked *Manual* state exactly what a human reviewer must confirm.
- **Grounded in the canon, not competing with it.** Each section cites the authorities it operationalizes. Where standards are still emerging (NIST's COSAiS control overlays for AI agent systems, targeted 2026–27), this policy anticipates them.

**Threat context.** This is not theoretical. Between January and February 2026, researchers filed 30+ CVEs against MCP servers, clients, and infrastructure — the most severe (CVE-2025-6514, CVSS 9.6) affecting 437,000+ installed environments. Palo Alto Unit 42 measured a 78.3% attack success rate against an agent connected to five MCP servers. Documented in-the-wild attacks include a malicious MCP server that impersonated a legitimate email tool to exfiltrate customer data.

<!-- TODO (author pass): opening section on scope — this policy evaluates individual third-party servers pre-adoption; it does not cover agent-side/host hardening (see Anthropic ZT guide for that) or runtime monitoring. -->

## How scoring works

Each section below contains requirements evaluated as **pass / warn / fail / unverifiable**. Category results roll up into a weighted 0–100 score and letter grade (bands published in the open rubric). Two structural rules:

1. **"Cannot verify" is a finding, not a gap in the report.** A server whose capabilities cannot be inspected (closed source, no reachable tool schema) is capped at grade B regardless of other results. Unverifiability is itself risk signal.
2. **Weights and thresholds are public.** The full scoring logic lives in the open rubric repository. A score you can't audit is a score you shouldn't trust.

---

## §1 — Provenance & supply-chain integrity

**Intent.** Before evaluating *what a server does*, establish *where it comes from*. An MCP server is a supply-chain dependency with agent-level privileges: unmaintained, unattributable, or impersonated packages are the cheapest attack vector against agentic systems, and typosquatting an MCP server yields far more access than typosquatting an ordinary library.

- **§1.1 Registry presence.** The server is listed on the official MCP registry (registry.modelcontextprotocol.io) or a major curated directory, under an identifier consistent with its source repository.
  *Verified by:* `provenance.registry-listed`
- **§1.2 Source repository health.** The source is public and maintained: not archived, recent commit activity, an identifiable maintainer, a license, and a security policy (SECURITY.md).
  *Verified by:* `provenance.repo-health`
- **§1.3 Package integrity.** The published package (npm/PyPI) matches its claimed source repository, is not deprecated, has a plausible age/download history for its claimed role, and carries a build-provenance attestation where the ecosystem supports it (npm provenance/Sigstore).
  *Verified by:* `provenance.package-hygiene`

*References:* Anthropic ZT Part II ("Tool and framework supply chain risks") and Part IV Phase 2 ("Manage supply chain risks" — AI-BOM, dependency vetting); OWASP MCP Top 10 (supply-chain risk category); NSA MCP guidance (supply-chain considerations); OpenSSF Scorecard (methodological model). <!-- TODO: pin exact OWASP item IDs when Top 10 exits beta -->

## §2 — Capability scope & least privilege

**Intent.** The dominant risk in an MCP server is not a software bug — it is the *breadth of what its tools can legitimately do*. Anthropic's Zero Trust guide extends least privilege to "least agency": constrain not just access, but what each tool can do, how often, and where. A server exposing shell execution, unrestricted filesystem access, or arbitrary outbound network calls must justify that surface; a server combining them rarely can.

- **§2.1 Inspectable tool surface.** The server's tool schema (names, descriptions, input schemas) is obtainable without executing untrusted code — via a live `tools/list` on remote servers, registry metadata, or public source.
  *Verified by:* `capabilities.tool-surface` (unverifiable ⇒ grade cap, per scoring rules)
- **§2.2 High-risk capability disclosure.** Tools that execute processes, access the filesystem broadly, make dynamic outbound requests, or read credential material are identified and flagged; their necessity must be evident from the server's stated purpose.
  *Verified by:* `capabilities.tool-surface` (risk-keyword analysis)
- **§2.3 Capability minimalism.** *(Manual.)* The tool surface is no broader than the server's purpose requires; risky capabilities are separated rather than bundled into one server.

*References:* Anthropic ZT Part III ("Permission models," least agency; sandboxing as table stakes); OWASP MCP Top 10 (excessive permissions / over-privileged access); NSA MCP guidance; MCP spec Security Best Practices.

## §3 — Authentication & transport hardening

**Intent.** Since the June 2025 specification revision, remote MCP servers are OAuth 2.1 resource servers — full stop. A remote server accepting anonymous tool calls, or one that mishandles token audience binding, exposes every connected agent. Local (stdio) servers inherit host-process privileges by design; that is expected, but shifts the burden to §1/§2 scrutiny.

- **§3.1 Transport security.** Remote endpoints are HTTPS-only with valid TLS.
  *Verified by:* `transport.https`
- **§3.2 Authentication required.** Remote servers reject unauthenticated requests (401 with `WWW-Authenticate`) rather than serving tools anonymously. <!-- TODO (author pass): note the legitimate-public-server exception (docs servers etc.) and how it's scored -->
  *Verified by:* `transport.auth-required`
- **§3.3 OAuth 2.1 conformance.** Remote servers publish protected-resource metadata (`/.well-known/oauth-protected-resource`) and follow the June 2025 authorization spec, including RFC 8707 resource indicators binding tokens to the specific server.
  *Verified by:* `transport.oauth-metadata`
- **§3.4 Credential handling (stdio).** *(Manual.)* Local servers document which environment credentials they read and why; secrets are scoped, not repurposed org-wide tokens.

*References:* MCP spec 2025-06-18 authorization (OAuth 2.1 + PKCE, RFC 8707); MCP spec Security Best Practices; Anthropic ZT Part III ("Agent identity and authentication" — short-lived tokens over static keys); OWASP MCP Security Cheat Sheet.

## §4 — Dependency & vulnerability hygiene

**Intent.** An MCP server is only as safe as its dependency tree, and agentic servers are typically young packages assembled quickly from many transitive dependencies — each one attack surface acquired for no functional gain.

- **§4.1 No known vulnerabilities.** The published package has no unresolved advisories in OSV.dev / GitHub Advisory Database at the evaluated version.
  *Verified by:* `vulns.osv`
- **§4.2 Dependency footprint.** *(Manual in v1.)* The dependency tree is proportionate to function; duplicated capability (multiple HTTP clients, JSON parsers) is a smell.

*References:* Anthropic ZT Part IV Phase 2 (AI-BOM integration); OSV.dev / GHSA; OWASP MCP Top 10 (vulnerable components).

## §5 — Tool-description integrity

**Intent.** Tool descriptions are executable in a sense no traditional metadata is: they are loaded into the model's context and *followed*. A poisoned description — hidden instructions, invisible Unicode, directives to prefer this tool over another — attacks the agent without the tool ever being invoked. This is the documented "tool poisoning" class: falsified descriptors, schemas, or metadata leading agents into unintended action.

- **§5.1 No hidden instructions.** Descriptions contain no invisible/zero-width characters, no imperative instructions addressed to the model ("ignore previous…", "do not tell the user…"), and no embedded instruction payloads in schema fields.
  *Verified by:* `poisoning.patterns`
- **§5.2 No cross-tool interference.** Descriptions do not instruct the agent to prefer, replace, or intercept other tools ("use this instead of…"), and contain no unexplained external URLs.
  *Verified by:* `poisoning.patterns`
- **§5.3 Description stability.** The tool schema does not change silently between evaluations; material changes to names, descriptions, or input schemas after adoption ("rug pulls") are surfaced by re-scanning.
  *Verified by:* `capabilities.tool-surface` (schema hash comparison across scans)

*References:* Anthropic ZT Part II ("Tool poisoning" — including the in-the-wild email-tool impersonation case); Invariant Labs tool-poisoning research (now Snyk); OWASP MCP Top 10 (tool poisoning / prompt injection categories).

## §6 — Toxic flows (tool combinations)

**Intent.** Individually safe tools compose into unsafe systems: a file-reader plus an outbound-network tool is an exfiltration pipeline; a browser tool plus shell access is remote code execution. Risk assessment that stops at individual tools misses the failure mode that actually compromises agents — the documented email-exfiltration attack worked by *combining* two tools, neither of which was individually malicious.

- **§6.1 Combination review.** *(Manual — not yet automatically verified; automation is on the rubric roadmap.)* Before adoption, enumerate the crossing of this server's capabilities with those of already-connected servers: read-capability × write/send-capability pairs deserve explicit sign-off.
- **§6.2 Blast-radius containment.** *(Manual.)* Agents connecting this server run with sandboxing and egress controls appropriate to the combined tool surface, not just this server's own.

*References:* Anthropic ZT Part II (cross-tool attack case) and Part III (sandboxing, least agency); Invariant Labs / Snyk "toxic flows" analysis; NIST COSAiS multi-agent overlay (draft).

---

## Using this policy

- **Self-serve verification:** run any server through the companion scorecard tool at [mcpscorecard.dev](https://mcpscorecard.dev) — it executes every *Verified by* check above and links each finding back to its section here.
- **The open rubric:** the exact logic, weights, and thresholds are public at [github.com/bluemotionlabs/mcpscorecard](https://github.com/bluemotionlabs/mcpscorecard).
- <!-- TODO (author pass): consulting CTA — deeper review, custom policy adoption, remediation. -->

*Maintained by <!-- TODO: byline / bluemotionlabs.com -->. This document reflects the maintainer's professional judgment, informed by the cited sources; it is an evaluation framework, not compliance assurance.*
