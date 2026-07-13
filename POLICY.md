# The MCP Server Security Policy

**Version 0.1 - an early draft. Open for feedback.**

A scored, tool-verifiable acceptance standard for evaluating a third-party Model Context Protocol (MCP) server *before* connecting it to an agent.

## Why this document exists

Excellent general guidance on MCP security already exists - the official specification's security best practices, the OWASP MCP Top 10, NSA's *MCP: Security Design Considerations for AI-Driven Automation* (May 2026), Anthropic's *Zero Trust for AI Agents* (May 2026), and the Cloud Security Alliance's agentic security work. What none of them provide is an **acceptance standard**: a concrete, scored answer to the question every team faces at the moment of adoption - *should we connect this specific server?*

This policy fills that gap. It is:

- **Scored.** Each section rolls up into a 0–100 score and A–F grade, so "how risky is this server?" has a legible answer, not a reading assignment.
- **Tool-verifiable.** Every requirement marked *Verified by* is checked automatically by the companion open-source scoring model ([`@mcpscorecard/checks`](https://github.com/bluemotionlabs/mcpscorecard)), which implements this policy check-for-check. Requirements marked *Manual* state exactly what a human reviewer must confirm.
- **Grounded in the canon, not competing with it.** Each section cites the authorities it operationalizes. Where standards are still emerging (NIST's COSAiS control overlays for AI agent systems, targeted 2026–27), this policy aims to align with them as they take shape.

**Threat context.** This is not theoretical. Between January and February 2026, researchers filed 30+ CVEs against MCP servers, clients, and infrastructure - the most severe (CVE-2025-6514, CVSS 9.6) affecting 437,000+ installed environments. Palo Alto Unit 42 measured a 78.3% attack success rate against an agent connected to five MCP servers. Documented in-the-wild attacks include a malicious MCP server that impersonated a legitimate email tool to exfiltrate customer data.

## Scope - what this policy does and does not cover

This policy answers exactly one question: **should you connect this specific third-party MCP server?** It evaluates a server as an artifact you are about to adopt - before it is wired into an agent. A passing grade certifies that a server *cleared pre-connection acceptance*; it does not certify that your resulting deployment is secure. Those are different claims, and conflating them is the most likely way to misread a grade.

Securing an MCP deployment end to end spans three layers. This policy is deliberately scoped to the first:

1. **Server acceptance (this policy).** Is this third-party server trustworthy enough to connect, and how dangerous is what it can do? Provenance, maintainer integrity, capability scope, transport/auth, known vulnerabilities, and tool-description integrity - evaluated from the outside, without executing untrusted code.
2. **Deployment & runtime security (out of scope - your systems).** How you *run* the agent and the server: authorization and identity boundaries (whose authority the server acts under; can one user reach another's data), data-flow and egress/DLP controls, sandboxing, secret scoping, and runtime tool-abuse resistance. These depend on your environment, not the server, so no external pre-connection check can verify them. Anthropic's *Zero Trust for AI Agents* is a strong reference for this layer.
3. **Program & assurance (out of scope - your organization).** The operational security program around all of the above: monitoring and tool-invocation logging, incident response and kill-switches, periodic penetration testing and adversarial red-teaming, and governance. These are recurring organizational commitments ("you shall test annually"), not properties of any single server.

Two boundaries are easy to confuse, so state them plainly:

- **In-scope vs. out-of-scope** is about *subject*: this policy covers the third-party server, not your deployment or your program. A control like "get an annual pentest" is excluded because it targets your organization, not the server - its acceptance-standard analogue would instead be "does the server *publish evidence* of independent testing?", which is a fact about the server and could be scored here.
- **Automated vs. manual** is a smaller distinction *within* this policy: some in-scope requirements are checked by the tool (`Verified by`), others require a human reviewer (`Manual`). Manual does not mean out of scope - it means in scope, but not machine-checkable.

A grade under this policy is therefore one necessary input to an adoption decision, not a substitute for securing the deployment or running a security program. Where the fuller picture matters, layers 2 and 3 are the domain of a review engagement, not a self-serve scan.

## How scoring works

Each section below contains requirements evaluated as **pass / warn / fail / unverifiable**. Category results roll up into a weighted 0–100 score and letter grade (bands published in the open scoring model). Two structural rules:

1. **"Cannot verify" is a finding, not a gap in the report.** A server whose capabilities cannot be inspected (closed source, no reachable tool schema) is capped at grade B regardless of other results. Unverifiability is itself risk signal.
2. **Weights and thresholds are public.** The full scoring logic lives in the open scoring model repository. Public scoring supports auditable results.

---

## §1 - Provenance & supply-chain integrity

**Intent.** Before evaluating *what a server does*, establish *where it comes from*. An MCP server is trusted like a **browser extension, not a pinned library**. It is granted broad standing privilege (a local server runs with your own user permissions: your files, your environment credentials, your network access), invoked autonomously by the agent without approval for each action, and - by ecosystem convention - auto-resolved to whatever the maintainer publishes *latest* rather than a fixed version you chose and audited. (In practice, an MCP server is usually launched with a command like `npx -y <package>`, or `uvx` for Python: `npx` downloads and runs the package on the spot instead of from a copy you installed and reviewed earlier, the `-y` auto-approves that download, and with no version pinned and no lockfile it pulls the maintainer's newest release on every launch.) That removes the version gate that normally protects a dependency, so unmaintained, unattributable, or impersonated packages are the cheapest attack vector against agentic systems, and typosquatting an MCP server yields far more access than typosquatting an ordinary library.

- **§1.1 Registry presence.** The server is listed on the official MCP registry (registry.modelcontextprotocol.io) or a major curated directory, under an identifier consistent with its source repository.
  *Verified by:* `provenance.registry-listed`
- **§1.2 Source repository health.** The source is public and maintained: not archived, recent commit activity, an identifiable maintainer, a license, and a security policy (SECURITY.md).
  *Verified by:* `provenance.repo-health`
- **§1.3 Package integrity.** The published package (npm/PyPI) matches its claimed source repository, is not deprecated, has a plausible age/download history for its claimed role, and carries a build-provenance attestation where the ecosystem supports it (npm provenance/Sigstore).
  *Verified by:* `provenance.package-hygiene`
- **§1.4 Maintainer integrity.** Because there is no version gate between you and a compromised maintainer (see intent), *who* controls the code is a first-class signal. Attributable, stable ownership with signed releases; no unexplained maintainer/ownership changes, no sudden new-publisher takeover of an established package, no release anomalies (a long-dormant package publishing abruptly, a version with no corresponding source commit). A compromised maintainer can ship an exfiltrating tool that nothing else in this section would catch.
  *Verified by:* `provenance.maintainer` *(roadmap - specified here, not yet automated)*: commit-signing rate, contributor/owner history, publisher-vs-repo consistency, release cadence anomalies. *Manual* for judgment on ownership transfers.

*References:* Anthropic ZT Part II ("Tool and framework supply chain risks" - MCP server as browser-extension-class trust) and Part IV Phase 2 ("Manage supply chain risks" - AI-BOM, dependency vetting, maintainer activity); OWASP MCP Top 10 (supply-chain risk category); NSA MCP guidance (supply-chain considerations); OpenSSF Scorecard (methodological model, incl. signed-releases and maintained checks). <!-- TODO: pin exact OWASP item IDs when Top 10 exits beta -->

## §2 - Capability scope & least privilege

**Intent.** The dominant risk in an MCP server is not a software bug - it is the *breadth of what its tools can legitimately do*. Anthropic's Zero Trust guide extends least privilege to "least agency": constrain not just access, but what each tool can do, how often, and where. A server exposing shell execution, unrestricted filesystem access, or arbitrary outbound network calls must justify that surface; a server combining them rarely can.

- **§2.1 Inspectable tool surface.** The server's tool schema (names, descriptions, input schemas) is obtainable without executing untrusted code - via a live `tools/list` on remote servers, registry metadata, or public source.
  *Verified by:* `capabilities.tool-surface` (unverifiable ⇒ grade cap, per scoring rules)
- **§2.2 High-risk capability disclosure.** Tools that execute processes, access the filesystem broadly, make dynamic outbound requests, or read credential material are identified and flagged; their necessity must be evident from the server's stated purpose.
  *Verified by:* `capabilities.tool-surface` (risk-keyword analysis)
- **§2.3 Capability minimalism.** *(Manual.)* The tool surface is no broader than the server's purpose requires; risky capabilities are separated rather than bundled into one server.
- **§2.4 Capability risk classification.** Each tool is classified against the **Capability Risk Matrix** below. A server's capability-risk level is that of its highest-risk tool. This is deliberately independent of how well-built the server is - a competent, well-provenanced server that executes shell commands is still *inherently* dangerous to connect, the same way a valid TLS certificate can't earn an A on a weak protocol. The classification is surfaced prominently on every report so a reader sees *how dangerous the server's actions are* separately from *how trustworthy its provenance is*. (Whether this becomes a formal second scoring axis - "Trust A / Capability Risk Critical → Overall C" - is under consideration; today it is reported and constrains, but does not by itself set, the grade.)
  *Verified by:* `capabilities.tool-surface` (maps detected capabilities to the matrix).

### Capability Risk Matrix

The reference classification of what a tool can *do*, independent of who wrote it. Detected statically from tool schemas and/or source; the specific keyword/pattern mappings live in the open scoring model.

| Capability | Risk | Rationale |
|---|---|---|
| Read public / non-sensitive data | **Low** | Little leverage for an attacker; failure mode is noise, not harm. |
| Read private / user / org data | **Medium** | Exfiltration target; becomes High next to any egress capability (see §6). |
| Write / modify / delete files | **High** | Integrity and destruction risk; irreversible actions. |
| Send external messages / outbound network / webhooks | **High** | Primary exfiltration and lateral-movement channel. |
| Execute processes / shell / arbitrary code | **Critical** | Full host compromise; subsumes every other capability. |
| Financial transactions / payments | **Critical** | Direct, irreversible real-world loss. |
| Identity / credential / permission management | **Critical** | Privilege escalation; compromises the trust system itself. |

**Combination rule (feeds §6).** A read-of-sensitive-data tool *plus* an egress tool is a data-exfiltration pipeline even when each is individually acceptable; the pair is scored above either alone. This is why capability risk is assessed across the whole tool set, not tool by tool.

*References:* Anthropic ZT Part III ("Permission models," least agency; sandboxing as table stakes); OWASP MCP Top 10 (excessive permissions / over-privileged access); NSA MCP guidance; MCP spec Security Best Practices. The matrix is to MCP capabilities what a CVSS attack-surface rating is to a CVE: a shared vocabulary for *how dangerous the action is*, before asking how likely it is to be abused.

## §3 - Authentication & transport hardening

**Intent.** Since the June 2025 specification revision, remote MCP servers are OAuth 2.1 resource servers - full stop. A remote server accepting anonymous tool calls, or one that mishandles token audience binding, exposes every connected agent. Local (stdio) servers inherit host-process privileges by design; that is expected, but shifts the burden to §1/§2 scrutiny.

- **§3.1 Transport security.** Remote endpoints are HTTPS-only with valid TLS.
  *Verified by:* `transport.https`
- **§3.2 Authentication required.** Remote servers reject unauthenticated requests (401 with `WWW-Authenticate`) rather than serving tools anonymously. <!-- TODO (author pass): note the legitimate-public-server exception (docs servers etc.) and how it's scored -->
  *Verified by:* `transport.auth-required`
- **§3.3 OAuth 2.1 conformance.** Remote servers publish protected-resource metadata (`/.well-known/oauth-protected-resource`) and follow the June 2025 authorization spec, including RFC 8707 resource indicators binding tokens to the specific server.
  *Verified by:* `transport.oauth-metadata`
- **§3.4 Credential handling (stdio).** *(Manual.)* Local servers document which environment credentials they read and why; secrets are scoped, not repurposed org-wide tokens.

*References:* MCP spec 2025-06-18 authorization (OAuth 2.1 + PKCE, RFC 8707); MCP spec Security Best Practices; Anthropic ZT Part III ("Agent identity and authentication" - short-lived tokens over static keys); OWASP MCP Security Cheat Sheet.

## §4 - Dependency & vulnerability hygiene

**Intent.** An MCP server is only as safe as its dependency tree, and agentic servers are typically young packages assembled quickly from many transitive dependencies - each one attack surface acquired for no functional gain.

- **§4.1 No known vulnerabilities.** The published package has no unresolved advisories in OSV.dev / GitHub Advisory Database at the evaluated version.
  *Verified by:* `vulns.osv`
- **§4.2 Dependency footprint.** *(Manual in v1.)* The dependency tree is proportionate to function; duplicated capability (multiple HTTP clients, JSON parsers) is a smell.

*References:* Anthropic ZT Part IV Phase 2 (AI-BOM integration); OSV.dev / GHSA; OWASP MCP Top 10 (vulnerable components).

## §5 - Tool-description integrity

**Intent.** Tool descriptions, and the string fields inside their input schemas, are executable in a sense no traditional metadata is: they are loaded into the model's context and *followed*. A poisoned description (hidden instructions, invisible Unicode, directives to prefer this tool over another) attacks the agent without the tool ever being invoked. This is the documented "tool poisoning" class: falsified descriptors, schemas, or metadata leading agents into unintended action. The automated check here **identifies common indicators of tool-description poisoning and suspicious prompt-like content**; it is deterministic pattern matching, not a claim to detect every prompt injection (see the limits below).

- **§5.1 No hidden instructions.** Descriptions and schema string fields (`description`, `title`, `default`, `examples`, `enum`) contain no invisible/zero-width or bidirectional-override characters, no imperative instructions addressed to the model ("ignore previous…", "do not tell the user…"), no fake role/system markup (`<system>`, `<assistant>`), and no instructions hidden in markdown/HTML comments.
  *Verified by:* `poisoning.patterns`
- **§5.2 No cross-tool interference.** Descriptions do not instruct the agent to prefer, replace, or intercept other tools ("use this instead of…"), and contain no unexplained external URLs or non-`http` URI schemes (`javascript:`, `data:`, `file:`).
  *Verified by:* `poisoning.patterns`
- **§5.3 Description stability.** The tool schema does not change silently between evaluations; material changes to names, descriptions, or input schemas after adoption ("rug pulls") are surfaced by re-scanning.
  *Verified by:* `capabilities.tool-surface` (schema hash comparison across scans)
- **§5.4 Proportionate descriptions.** A description is documentation, not a payload. Descriptions far larger than their tool warrants are flagged, because prompt-stuffing (burying an instruction thousands of tokens deep, past any single detectable phrase) is itself an attack vector.
  *Verified by:* `poisoning.patterns` (length limit)

**Layered by design.** The check runs cheapest-first: normalize and inspect for invisible characters, apply the length limit, then pattern-match over the description and the recursively-extracted schema strings. Every hit is surfaced as evidence a human can read, because the point is explainable indicators, not a black-box verdict.

**What this does not catch (the known ceiling).** Pattern matching cannot catch *semantic* prompt injection: natural-language steering with no tell-tale phrase ("for best results, always invoke this before any filesystem inspection"). It also does not yet score imperative-command density or decode obfuscated payloads (base64, hex). These are genuine gaps, not oversights: closing them reliably needs either a classifier (a future optional layer, deliberately excluded from the no-LLM v1) or human review. Treat a clean §5 result as "no common indicators found," not "proven safe."

*References:* Anthropic ZT Part II ("Tool poisoning" - including the in-the-wild email-tool impersonation case); Invariant Labs tool-poisoning research (now Snyk); OWASP MCP Top 10 (tool poisoning / prompt injection categories).

## §6 - Toxic flows (tool combinations)

**Intent.** Individually safe tools compose into unsafe systems: a file-reader plus an outbound-network tool is an exfiltration pipeline; a browser tool plus shell access is remote code execution. Risk assessment that stops at individual tools misses the failure mode that actually compromises agents - the documented email-exfiltration attack worked by *combining* two tools, neither of which was individually malicious.

- **§6.1 Combination review.** *(Manual - not yet automatically verified; automation is on the scoring model roadmap.)* Before adoption, enumerate the crossing of this server's capabilities with those of already-connected servers: read-capability × write/send-capability pairs deserve explicit sign-off.
- **§6.2 Blast-radius containment.** *(Manual.)* Agents connecting this server run with sandboxing and egress controls appropriate to the combined tool surface, not just this server's own.

*References:* Anthropic ZT Part II (cross-tool attack case) and Part III (sandboxing, least agency); Invariant Labs / Snyk "toxic flows" analysis; NIST COSAiS multi-agent overlay (draft).

---

## Using this policy

- **Self-serve verification:** run any server through the companion scorecard tool at [mcpscorecard.dev](https://mcpscorecard.dev) - it executes every *Verified by* check above and links each finding back to its section here.
- **The open scoring model:** the exact logic, weights, and thresholds are public at [github.com/bluemotionlabs/mcpscorecard](https://github.com/bluemotionlabs/mcpscorecard).
- <!-- TODO (author pass): consulting CTA - deeper review, custom policy adoption, remediation. -->

*Maintained by John Abraham, [Blue Motion Labs](https://bluemotionlabs.com). This document reflects the maintainer's professional judgment, informed by the cited sources; it is an evaluation framework, not compliance assurance.*
