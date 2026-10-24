# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities **privately** via GitHub's private
vulnerability reporting for this repository (Security → Report a
vulnerability). Do not open public issues for security problems, and never
attach or link to real evidence.

Include, if possible:

- affected version or commit SHA;
- OS/architecture and toolchain;
- a minimal synthetic reproduction;
- impact you believe it has (crash, incorrect evidence interpretation,
  integrity bypass, disclosure);
- safe diagnostics only.

## Scope

GhostTrace is designed under the assumption that **all imported files, native
filenames, SQLite schemas, XML/log fields, URLs, manifest JSON, and rule
parameters may be malicious** (plan Section 13). In-scope issues include:
memory-safety defects in first-party code; resource exhaustion or hang from a
crafted artifact; integrity/signature bypass; path escapes in capture,
restore, or package handling; injection into reports/CSV/terminal; private-key
leakage; and network activity in the offline-by-default workflow.

Out of scope: a fully compromised host (GhostTrace detects portable integrity
violations but cannot defend against a compromised analysis machine); legal
admissibility questions; and vulnerabilities in dependencies that do not
manifest in our feature set (report upstream, link the CVE).

## Supported versions

Until the first public release, only the latest `main` commit receives
security fixes; no backports are promised. Supported version ranges and
response expectations are published with each release.

## Handling rules

- No security fix ships without a deterministic regression test.
- Dependency exceptions must name the advisory, applicability, rationale,
  owner, and expiry.
- Signing keys, tokens, and trusted-key lists never live in this repository.
