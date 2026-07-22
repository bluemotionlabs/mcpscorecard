# The MCP Server Security Policy

**Version 0.2 draft — open for feedback.**  
*Companion to the v0.1 policy. This draft is not yet the live policy; see [POLICY.md](POLICY.md) for the current published text.*

A scored, tool-verifiable acceptance standard for evaluating a third-party Model Context Protocol (MCP) server *before* connecting it to an agent.

## Why this document exists

Excellent general guidance on MCP security already exists — the official specification's security best practices, the OWASP MCP Top 10 (MCP01–MCP10), NSA's *MCP: Security Design Considerations for AI-Driven Automation* (May 2026), Anthropic's *Zero Trust for AI Agents* (May 2026), and the Cloud Security Alliance's / Coalition for Secure AI agentic security work. What none of them provide is an **acceptance standard**: a concrete, scored answer to the question every team faces at the moment of adoption — *should we connect this specific server?*

This policy fills that gap. It is:

- **Dual-scored.** Every report publishes two independent grades — **Trust** (is this server who it claims to be, and is its declared surface intact?) and **Exposure** (how dangerous are its capabilities?) — plus a **composite** that cannot be better than either axis allows. Good provenance cannot paper over shell execution; a read-only server cannot earn an A on broken identity.
- **Tool-verifiable.** Every requirement marked *Verified by* is checked automatically by the companion open-source scoring model ([`@mcpscorecard/checks`](https://github.com/bluemotionlabs/mcpscorecard)), which implements this policy check-for-check. Requirements marked *Manual* state exactly what a human reviewer must confirm. Requirements marked *Roadmap* are specified here so the standard leads the implementation; they are not yet automated.
- **Grounded in the canon, not competing with it.** Each section cites the authorities it operationalizes, including the official MCP registry's namespace and package-ownership verification rules. Where standards are still emerging (NIST's COSAiS control overlays; CTMS sealed tool manifests), this policy aims to align with them as they take shape.

**Threat context.** This is not theoretical. Between January and February 2026, researchers filed 30+ CVEs against MCP servers, clients, and infrastructure. Palo Alto Unit 42 measured a 78.3% attack success rate against an agent connected to five MCP servers. Documented authenticity failures include:

- **postmark-mcp (September 2025)** — an npm package that impersonated a legitimate email MCP (canonical source was GitHub-only), built trust over 15 clean versions, then BCC'd outbound mail to an attacker.
- **SANDWORM_MODE (February 2026)** — typosquatted npm packages that injected rogue MCP servers into IDE agent configs to harvest credentials.
- **Mini Shai-Hulud (May 2026)** — malicious packages shipped with *valid* Sigstore / SLSA provenance: attestation proved the CI pipeline ran, not that the code was safe.

These incidents define the authenticity problem this version centers: *identity binding and impersonation resistance*, not merely "has a LICENSE and a repo."

## Scope — what this policy does and does not cover

This policy answers exactly one question: **should you connect this specific third-party MCP server?** It evaluates a server as an artifact you are about to adopt — before it is wired into an agent. Clearing acceptance certifies pre-connection triage; it does not certify that your resulting deployment is secure. Those are different claims, and conflating them is the most likely way to misread a grade.

Securing an MCP deployment end to end spans three layers. This policy is deliberately scoped to the first:

1. **Server acceptance (this policy).** Is this third-party server authentic enough to connect, is its declared surface intact, and how dangerous is what it can do? Identity binding, publisher integrity, capability scope, transport/auth, known vulnerabilities, and instruction integrity — evaluated from the outside, without executing untrusted code.
2. **Deployment & runtime security (out of scope — your systems).** How you *run* the agent and the server: authorization and identity boundaries, data-flow and egress/DLP controls, sandboxing, secret scoping, and runtime tool-abuse resistance. Anthropic's *Zero Trust for AI Agents* is a strong reference for this layer.
3. **Program & assurance (out of scope — your organization).** Monitoring, incident response, periodic adversarial testing, and governance — including discovery of *shadow* MCP servers (OWASP MCP09), which is an organizational control, not a property of any single scanned artifact.

Two boundaries are easy to confuse, so state them plainly:

- **In-scope vs. out-of-scope** is about *subject*: this policy covers the third-party server, not your deployment or your program.
- **Automated vs. manual** is a smaller distinction *within* this policy: some in-scope requirements are checked by the tool (`Verified by`), others require a human reviewer (`Manual`). Manual does not mean out of scope.

A grade under this policy is one necessary input to an adoption decision, not a substitute for securing the deployment or running a security program.

## How scoring works

Each requirement below is evaluated as **pass / warn / fail / info / unverifiable**. Results roll up into two weighted 0–100 scores and letter grades. Weights, bands, and caps live in the open scoring model — public by design.

### Dual axes

| Axis | Question | Primary sections |
|---|---|---|
| **Trust** | Is this server who it claims to be, and is its model-facing surface intact? | §1, §3 (remote), §4, §5, §7 |
| **Exposure** | How much damage can it do if connected (or compromised)? | §2, §6 |

**Composite grade** = `min(TrustGrade, ExposureCap)`, where ExposureCap is derived from the server's Capability Risk level (§2.4):

| Highest capability risk | Composite cap |
|---|---|
| **Critical** (shell / financial / identity admin) | Max **C** |
| **High** (write/delete, egress, webhooks) | Max **B** |
| **Medium** (read private / user / org data) | No cap |
| **Low** (read public / non-sensitive) | No cap |

Worked examples:

- Verified publisher + shell tools → Trust A / Exposure Critical → **composite C**
- Unknown maintainer + read-only tools → Trust D / Exposure Low → **composite D**
- Verified publisher + read-only tools → Trust A / Exposure Low → **composite A**
- High-confidence typosquat → Trust F → **composite F** regardless of tools

### Structural rules

1. **"Cannot verify" is a finding, not a gap.** A server whose tool surface cannot be inspected is capped at Exposure **B**. Unverifiability is itself risk signal.
2. **Authenticity hard gates (Trust).** Broken package↔registry↔source binding (§1.2) caps Trust at **D**. High-confidence impersonation (§1.3) forces Trust **F**. Critical instruction-integrity indicators (§5.2 credential-priority directives) fail Trust and prevent a composite of A or B.
3. **Capabilities are non-compensatable.** Provenance cannot buy down Exposure. The Exposure axis exists so a dangerous-but-authentic server never looks "safe" under a single blended number.
4. **Transport checks are conditional.** Local (stdio) servers are not scored on HTTPS/OAuth; those checks apply to remote servers only (§3). Stdio servers inherit host privileges by design — scrutiny shifts to §1 and §2.
5. **Weights and thresholds are public.** Public scoring supports auditable results.

### Identity binding chain (Trust foundation)

Authenticity is a chain, not a checklist. A server that breaks any link cannot earn a high Trust grade:

```
Verified registry namespace
  → package ownership binding (e.g. npm mcpName)
  → published package / artifact
  → claimed source repository
  → release commit / tag (and, where present, build attestation)
  → declared tool metadata (hash baseline; signed manifest when available)
```

Search similarity ("looks like filesystem") is not the same as verified binding. Provenance attestation proves *build origin*, not *intent* — valid SLSA/Sigstore on a malicious build is still a Trust signal about custody, not a safety certificate.

---

## §1 — Identity & supply-chain authenticity

**Intent.** Before evaluating *what a server does*, establish *who controls it* and *whether the artifact is bound to that identity*. An MCP server is trusted like a **browser extension, not a pinned library**. It is granted broad standing privilege, invoked autonomously by the agent, and — by ecosystem convention — often launched with `npx -y <package>` or `uvx` so that every invocation pulls the maintainer's *latest* release with no version pin, no lockfile, and no review window. That removes the version gate that normally protects a dependency. Unattributable, impersonated, or suddenly-taken-over packages are the cheapest attack vector against agentic systems; typosquatting an MCP server yields far more access than typosquatting an ordinary library.

Authenticity rank order for this section: **binding → impersonation → publisher/release integrity → verified provenance → repository cosmetics.**

- **§1.1 Verified registry identity.** The server has an entry on the official MCP registry (`registry.modelcontextprotocol.io`) under a namespace whose authentication method is recorded (GitHub OAuth for `io.github.{owner}/*`, or DNS/HTTP domain verification for reverse-DNS namespaces). For GitHub namespaces, the namespace owner matches the linked repository owner; for domain namespaces, domain verification status is confirmed. A fuzzy search hit without verified namespace binding is a *warn*, not a *pass*. Absence from the registry is not automatically a hard fail — many legitimate servers are unpublished — but it removes a strong authenticity signal.
  *Verified by:* `identity.registry-verified` *(roadmap relative to v0.1 `provenance.registry-listed`; replaces search-only matching)*

- **§1.2 Package ↔ registry ↔ source binding.** The published package is cryptographically and metadata-bound to the registry identity and claimed source. For npm: `package.json` includes `mcpName` exactly matching the registry `server.json` `name`; registry `packages[].identifier` matches the scanned package; the package `repository` field matches the claimed source repo; GitHub namespaces require `io.github.{owner}` consistency with the repo owner. Equivalent ecosystem bindings apply for PyPI, NuGet, Cargo, and MCPB (`fileSha256` where required). A package that exists but fails binding is a *fail*; a lookalike package with a broken chain is treated as an impersonation signal under §1.3.
  *Verified by:* `identity.package-binding` *(roadmap — highest-priority authenticity check; subsumes the shallow repo-field match in v0.1 `provenance.package-hygiene`)*

- **§1.3 Impersonation & namespace risk.** The server does not present high-confidence impersonation indicators: lookalike / typosquat names relative to well-known MCP packages and registry entries; brand or vendor strings without a verified namespace; npm-only distribution when the canonical project is GitHub-only (the postmark pattern); young publisher accounts paired with high name similarity to established servers.
  *Verified by:* `identity.impersonation` *(roadmap)*  
  *Manual:* judgment on brand disputes and intentional forks that disclose the relationship.

- **§1.4 Publisher & maintainer integrity.** Because there is no version gate between you and a compromised maintainer, *who* controls the publishing account is a first-class signal. Signals include: publisher account age; presence of 2FA / verified-publisher status where the ecosystem exposes it; organization vs. individual publisher; publisher↔repository-owner consistency; ownership transfers and maintainer churn; release tags that do not match published versions; long dormancy followed by a sudden publish burst.
  *Verified by:* `identity.publisher` *(roadmap — supersedes v0.1 `provenance.maintainer`)*  
  *Manual:* judgment on legitimate ownership transfers and org restructures.

- **§1.5 Release & install-time integrity.** The release stream and install path are consistent with a maintained, non-hostile package: release cadence is not anomalous relative to history; the `latest` dist-tag is not abnormally fresh for an established server without explanation; pre-release tags are not silently promoted; and install-time code paths (`preinstall` / `postinstall`, unexpected `bin` entries) that execute before the MCP server is even configured are disclosed and scrutinized. Floating `latest` without pin guidance is documented as residual risk under the `npx -y` model.
  *Verified by:* `identity.release-anomaly` *(roadmap)*

- **§1.6 Cryptographic build provenance.** Where the ecosystem supports it (npm provenance / Sigstore, SLSA attestations, signed GitHub release assets), the published artifact carries a build attestation that *verifies* — not merely exists — and binds to the claimed source repository and the commit/tag for the evaluated version (Rekor transparency-log inclusion when available). **Provenance verifies build origin, not intent.** An attestation that claims a different repository than §1.2 is a *fail*. Absence of attestation where the ecosystem supports it is a *warn*; ecosystems without attestation support yield *info*.
  *Verified by:* `identity.provenance-verified` *(roadmap — deep verification; replaces boolean "attestations present" in v0.1)*

- **§1.7 Source repository health.** The source is public and maintained: not archived, recent commit activity, an identifiable maintainer, a license, and a security policy (`SECURITY.md` with a disclosure contact). These are necessary hygiene signals; they do not outweigh a broken binding chain.
  *Verified by:* `provenance.repo-health`

*References:* Official MCP registry namespace authentication and package ownership verification (`mcpName`, DNS/HTTP domain auth); Anthropic ZT Part II (browser-extension-class trust) and Part IV Phase 2 (supply chain); OWASP MCP04 (supply chain) and MCP09 (shadow servers — org layer, out of scope here); NSA MCP guidance; OpenSSF Scorecard (signed releases, maintained); Coalition for Secure AI MCP Security (SBOM, signing, attestation); Sigstore / SLSA (build provenance limits).

---

## §2 — Capability scope & least privilege

**Intent.** The dominant risk in an MCP server is often not a software bug — it is the *breadth of what its tools can legitimately do*. Anthropic's Zero Trust guide extends least privilege to "least agency." A well-provenanced server that executes shell commands is still *inherently* dangerous to connect. Exposure scoring exists so that fact cannot be compensated away by Trust.

- **§2.1 Inspectable tool surface.** The server's tool schema (names, descriptions, input schemas) is obtainable without executing untrusted code — via a live `tools/list` on remote servers, registry metadata, or public source. Unverifiable ⇒ Exposure capped at **B**.
  *Verified by:* `capabilities.tool-surface`

- **§2.2 High-risk capability disclosure.** Tools that execute processes, access the filesystem broadly, make dynamic outbound requests, or read credential material are identified and flagged. When present, MCP tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`, and related hints) are treated as first-class disclosure signals and checked for consistency with observed patterns.
  *Verified by:* `capabilities.tool-surface` (risk-keyword / annotation analysis)

- **§2.3 Capability minimalism.** *(Manual.)* The tool surface is no broader than the server's purpose requires; risky capabilities are separated rather than bundled into one server.

- **§2.4 Capability risk classification.** Each tool is classified against the **Capability Risk Matrix** below. A server's Exposure level is that of its highest-risk tool (subject to §6 combination upgrades). This classification **sets the Exposure cap** on the composite grade — it is not merely "surfaced prominently."
  *Verified by:* `capabilities.tool-surface`

- **§2.5 Secret material in source.** *(Near-term.)* Published source / tarball does not contain hardcoded credentials, API keys, or high-entropy secrets distinct from documented env-var usage.
  *Verified by:* `capabilities.secret-scan` *(roadmap — OWASP MCP01)*

- **§2.6 Command-injection patterns.** *(Near-term.)* Source does not show common unsanitized user-input→exec/eval flows where process execution is present.
  *Verified by:* `capabilities.command-injection` *(roadmap — OWASP MCP05; heuristic, not proof of absence)*

### Capability Risk Matrix

The reference classification of what a tool can *do*, independent of who wrote it. Detected statically from tool schemas and/or source; keyword/pattern mappings live in the open scoring model.

| Capability | Risk | Rationale |
|---|---|---|
| Read public / non-sensitive data | **Low** | Little leverage; failure mode is noise, not harm. |
| Read private / user / org data | **Medium** | Exfiltration target; becomes High next to egress (§6). |
| Write / modify / delete files | **High** | Integrity and destruction risk; irreversible actions. |
| Send external messages / outbound network / webhooks | **High** | Primary exfiltration and lateral-movement channel. |
| Execute processes / shell / arbitrary code | **Critical** | Full host compromise; subsumes every other capability. |
| Financial transactions / payments | **Critical** | Direct, irreversible real-world loss. |
| Identity / credential / permission management | **Critical** | Privilege escalation; compromises the trust system itself. |

**Combination rule (feeds §6).** A read-of-sensitive-data tool *plus* an egress tool is a data-exfiltration pipeline even when each is individually acceptable; the pair raises Exposure above either alone.

*References:* Anthropic ZT Part III (least agency); OWASP MCP02 (scope creep), MCP05 (command injection); NSA MCP guidance; MCP spec Security Best Practices and tool annotations.

---

## §3 — Authentication & transport hardening

**Intent.** Since the June 2025 specification revision, remote MCP servers are OAuth 2.1 resource servers. A remote server accepting anonymous tool calls, or one that mishandles token audience binding, exposes every connected agent. Local (stdio) servers inherit host-process privileges by design; that is expected, and **transport requirements below do not apply to them** (reported as `info`). Scrutiny for stdio shifts to §1 and §2.

- **§3.1 Transport security.** Remote endpoints are HTTPS-only. Where feasible, certificate identity (CN/SAN) matches the declared server hostname.
  *Verified by:* `transport.https` *(remote only)*

- **§3.2 Authentication required.** Remote servers reject unauthenticated requests (401 with `WWW-Authenticate`) rather than serving tools anonymously.
  *Verified by:* `transport.auth-required` *(remote only)*  
  **Public read-only exception:** intentionally public servers (e.g. documentation / public-data tools) that document anonymous access as by design are scored as *warn* or *info* with evidence of the disclosure — not as a hard fail — provided they expose no credentialed or mutating tools. Judgment of "intentionally public" is *Manual* when ambiguous.

- **§3.3 OAuth 2.1 conformance.** Remote servers publish protected-resource metadata (`/.well-known/oauth-protected-resource`) and follow the authorization spec, including RFC 8707 resource indicators binding tokens to the specific server.
  *Verified by:* `transport.oauth-metadata` *(remote only)*

- **§3.4 Token audience & scope.** *(Near-term.)* Observable evidence that tokens are audience-bound and not blindly passed through; scopes are least-privilege where metadata exposes them.
  *Verified by:* `transport.oauth-scoping` *(roadmap — OWASP MCP01 / MCP07)*  
  *Manual:* review of token-passthrough and confused-deputy risk in server documentation and source.

- **§3.5 Credential handling (stdio).** *(Manual.)* Local servers document which environment credentials they read and why; secrets are scoped, not repurposed org-wide tokens.

*References:* MCP spec 2025-06-18 authorization (OAuth 2.1 + PKCE, RFC 8707); MCP spec Security Best Practices; Anthropic ZT Part III; OWASP MCP01, MCP07.

---

## §4 — Dependency & vulnerability hygiene

**Intent.** An MCP server is only as safe as its dependency tree. Agentic servers are often young packages assembled quickly from many transitive dependencies. Note the residual risk: consumers who install via `npx -y` may ignore lockfiles even when publishers provide them — lockfile and SBOM checks measure *publisher hygiene*, not a guarantee of consumer install integrity.

- **§4.1 No known vulnerabilities (package).** The published package has no unresolved advisories in OSV.dev / GitHub Advisory Database at the evaluated version.
  *Verified by:* `vulns.osv`

- **§4.2 Dependency footprint & pinning.** *(Near-term.)* A lockfile is present where the ecosystem expects one; dependency count is proportionate to function; duplicated capability (multiple HTTP clients, JSON parsers) is a smell.
  *Verified by:* `deps.lockfile` *(roadmap)*  
  *Manual:* judgment on proportionate footprint.

- **§4.3 Transitive advisories.** *(Near-term.)* Direct and transitive dependencies have no unresolved high/critical advisories at the locked versions.
  *Verified by:* `deps.own-audit` *(roadmap)*

- **§4.4 SBOM availability.** *(Near-term / bonus.)* The project publishes an SBOM (CycloneDX or SPDX) or equivalent machine-readable dependency inventory.
  *Verified by:* `deps.sbom` *(roadmap — soft-weighted)*

*References:* Anthropic ZT Part IV Phase 2 (AI-BOM); OSV.dev / GHSA; OWASP MCP04; Coalition for Secure AI MCP Security (SBOM, pinning).

---

## §5 — Server-supplied instruction integrity

**Intent.** A server hands the agent more model-facing text than tool descriptions alone. The `initialize` response's `instructions` field (which the MCP spec permits clients to inject into the **system prompt** — making it policy-coequal with the operator's own instructions), every tool `name` and `description`, string fields inside tool input schemas, and `prompts`/`resources` metadata are loaded into the model's context and *followed*. Any of them can carry a poisoned payload that steers the agent without the corresponding tool ever being invoked. The real risk is **authority**: an external server should describe what it does, not quietly become a co-author of the agent's operating policy.

Trust weighting treats instruction integrity as a first-class authenticity/integrity signal — especially `initialize.instructions` — not a secondary hygiene check.

- **§5.1 No hidden instructions.** Every server-supplied text channel — initialize `instructions`, tool names and descriptions, schema string fields (`description`, `title`, `default`, `examples`, `enum`), and prompt/resource metadata — contains no invisible/zero-width or bidirectional-override characters, no imperative instructions addressed to the model ("ignore previous…", "do not tell the user…"), no fake role/system markup (`<system>`, `<assistant>`), and no instructions hidden in markdown/HTML comments.
  *Verified by:* `poisoning.patterns`

- **§5.2 No excess authority over the agent.** Server text does not assert policy the agent's operator did not grant: no directive to read credentials, secrets, or environment variables ahead of the actual task (*critical* indicator — Trust fail / composite A–B blocked); no content-suppression directive ("never mention competitors"); no instruction to prefer, replace, or intercept other tools; no unexplained external URLs or non-`http` URI schemes (`javascript:`, `data:`, `file:`).
  *Verified by:* `poisoning.patterns`

- **§5.3 Instruction stability (rug-pull detection).** The tool schema does not change silently between evaluations; material changes to names, descriptions, or input schemas after adoption are surfaced by re-scanning (schema hash comparison). Aligns to OWASP MCP02 (scope creep) as well as MCP03.
  *Verified by:* `capabilities.tool-surface` (schema hash across scans)

- **§5.4 Proportionate text.** A description (or instructions field) is documentation, not a payload. Text far larger than its purpose warrants is flagged (prompt-stuffing).
  *Verified by:* `poisoning.patterns` (length limit)

- **§5.5 Signed tool metadata.** *(Roadmap.)* Publishers who ship a sealed / signed tool manifest (e.g. CTMS Sealed Tool Manifest / equivalent Sigstore- or Ed25519-signed canonical tool metadata) that verifies against the live `tools/list` earn a stronger integrity signal than hash-only stability. Verification failure (metadata drift against a published signature) is a *fail*.
  *Verified by:* `poisoning.signed-manifest` *(roadmap)*

**Layered by design.** Cheapest-first: collect every model-facing text item, apply length limits, then pattern-match (schema-derived strings skip description-only patterns so benign `$schema`/`$ref` URIs are not flagged). Hits are surfaced as readable evidence. Severity: credential-priority = *critical*; hidden instructions / fake markup = *fail*; softer over-reach = *warn*.

**What this does not catch (the known ceiling).** Pattern matching cannot catch *semantic* prompt injection (natural-language steering with no tell-tale phrase). Obfuscated payloads (base64, hex) and imperative-density scoring are near-term extensions without requiring an LLM. A full semantic classifier is an optional future layer, deliberately excluded from the no-LLM baseline. Treat a clean §5 result as "no common indicators found," not "proven safe."

*References:* Anthropic ZT Part II (tool poisoning; in-the-wild email impersonation); Invariant Labs / Snyk; OWASP MCP03, MCP06; MCP specification (`instructions`, `prompts`, `resources`); CTMS (Canonical Tool Manifest Specification) for signed metadata.

---

## §6 — Toxic flows (tool combinations)

**Intent.** Individually acceptable tools compose into unsafe systems: a file-reader plus an outbound-network tool is an exfiltration pipeline; a browser tool plus shell access is remote code execution. The documented email-exfiltration attack worked by *combining* tools, neither of which was individually flagged as malicious in isolation.

- **§6.1 Intra-server combination detection.** Within this server's own tool set, high-risk pairs are detected automatically and raise Exposure: read-sensitive × network-egress; filesystem-write × network-egress; shell-exec × any data-read; browser × shell.
  *Verified by:* `exposure.toxic-flows` *(roadmap — partially automatable from §2 capability hits)*

- **§6.2 Cross-server combination review.** *(Manual.)* Before adoption, enumerate crossings of this server's capabilities with already-connected servers; read × write/send pairs deserve explicit sign-off.
  *Roadmap:* multi-server toxic-flow analysis in a future scoring model revision.

- **§6.3 Blast-radius containment.** *(Manual.)* Agents connecting this server run with sandboxing and egress controls appropriate to the *combined* tool surface, not just this server's own. (Deployment-layer control; stated here so acceptance reviewers know what must be confirmed operationally.)

*References:* Anthropic ZT Part II–III; Invariant Labs / Snyk "toxic flows"; NIST COSAiS multi-agent overlay (draft); OWASP MCP02.

---

## §7 — Operational transparency

**Intent.** A server that operates silently leaves operators with no server-side evidence of abuse. OWASP MCP08 (lack of audit and telemetry) is currently under-covered by pre-connection scanners; this section scores *publisher-provided* transparency signals without pretending a static scan can verify runtime logging quality. Soft-weighted: absence is a *warn* / *info*, not a Trust hard fail, until signals are reliably machine-checkable at scale.

- **§7.1 Logging / telemetry disclosure.** The project documents whether and how it emits structured telemetry for tool invocations, errors, and auth events.
  *Verified by:* `audit.logging-exists` *(roadmap — soft-weighted)*  
  *Manual:* review of logging docs for adequacy.

- **§7.2 Egress & phone-home disclosure.** The maintainer documents network calls beyond documented tools (telemetry, license checks, update pings).
  *Manual* (near-term); *Roadmap* for static egress-pattern corroboration.

- **§7.3 Incident response contact.** `SECURITY.md` (or equivalent) publishes a clear vulnerability-reporting contact. Cross-references §1.7; the audit/response dimension is distinct from mere file presence.
  *Verified by:* `provenance.repo-health` (SECURITY.md presence) + *Manual* for contact adequacy.

*References:* OWASP MCP08; Anthropic ZT operational monitoring guidance; NSA MCP guidance (telemetry).

---

## OWASP MCP Top 10 mapping

| OWASP ID | Risk | Policy coverage |
|---|---|---|
| **MCP01** | Token mismanagement & secret exposure | §2.5 secret scan; §3.4–§3.5 credential / token handling |
| **MCP02** | Privilege escalation via scope creep | §2.3–§2.4; §5.3 rug-pull / schema drift; §6 combinations |
| **MCP03** | Tool poisoning | §5 (full channel coverage) |
| **MCP04** | Supply chain & dependency tampering | §1 (identity chain); §4 |
| **MCP05** | Command injection & execution | §2.2, §2.4, §2.6 |
| **MCP06** | Intent flow subversion | §5 (esp. `initialize.instructions`) |
| **MCP07** | Insufficient auth & authorization | §3 |
| **MCP08** | Lack of audit & telemetry | §7 |
| **MCP09** | Shadow MCP servers | **Out of scope** (organizational discovery / allowlisting — layer 3) |
| **MCP10** | Context injection & over-sharing | Partial via §2 read-sensitivity + §5 schema text; runtime context isolation is layer 2 |

---

## Check ID index (v0.2 draft)

| Check ID | Policy § | Status vs scoring model |
|---|---|---|
| `identity.registry-verified` | §1.1 | Roadmap (evolves `provenance.registry-listed`) |
| `identity.package-binding` | §1.2 | Roadmap |
| `identity.impersonation` | §1.3 | Roadmap |
| `identity.publisher` | §1.4 | Roadmap (evolves `provenance.maintainer`) |
| `identity.release-anomaly` | §1.5 | Roadmap |
| `identity.provenance-verified` | §1.6 | Roadmap (deepens package-hygiene attestation boolean) |
| `provenance.repo-health` | §1.7, §7.3 | Implemented |
| `capabilities.tool-surface` | §2.1–§2.4, §5.3 | Implemented |
| `capabilities.secret-scan` | §2.5 | Roadmap |
| `capabilities.command-injection` | §2.6 | Roadmap |
| `transport.https` | §3.1 | Implemented (remote only) |
| `transport.auth-required` | §3.2 | Implemented (remote only) |
| `transport.oauth-metadata` | §3.3 | Implemented (remote only) |
| `transport.oauth-scoping` | §3.4 | Roadmap |
| `vulns.osv` | §4.1 | Implemented |
| `deps.lockfile` | §4.2 | Roadmap |
| `deps.own-audit` | §4.3 | Roadmap |
| `deps.sbom` | §4.4 | Roadmap |
| `poisoning.patterns` | §5.1–§5.2, §5.4 | Implemented |
| `poisoning.signed-manifest` | §5.5 | Roadmap |
| `exposure.toxic-flows` | §6.1 | Roadmap |
| `audit.logging-exists` | §7.1 | Roadmap |

Legacy v0.1 IDs (`provenance.registry-listed`, `provenance.package-hygiene`, `provenance.maintainer`) remain meaningful until the scoring model migrates; this draft names the target IDs the implementation should converge on.

---

## Using this policy

- **Self-serve verification:** run any server through the companion scorecard at [mcpscorecard.dev](https://mcpscorecard.dev). Reports under v0.2 should show **Trust**, **Exposure**, and **composite**, with each finding linked to its section here.
- **Open scoring model:** weights, caps, pattern lists, and check code are public at [github.com/bluemotionlabs/mcpscorecard](https://github.com/bluemotionlabs/mcpscorecard).
- **Versioning:** until this draft is accepted, [POLICY.md](POLICY.md) (v0.1) remains the normative text. Migration of `@mcpscorecard/checks` to the dual-axis model and new check IDs is a separate implementation track.

*Maintained by John Abraham, [Blue Motion Labs](https://bluemotionlabs.com). This document reflects the maintainer's professional judgment, informed by the cited sources; it is an evaluation framework, not compliance assurance.*
