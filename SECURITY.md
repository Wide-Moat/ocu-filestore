# Security Policy

## Supported Versions

This project is pre-release (no stable version has been published). The table
below reflects the honest current state:

| Version range | Supported |
|---|---|
| `main` (pre-release, unreleased) | Yes — fixes target this branch |
| Any tagged pre-release (`v0.x.y`) | Rolling — superseded by the next tag; no backports during pre-release |
| None | A stable `v1.0` support window will be defined at first stable release |

Until a `v1.0.0` tag is cut, this project makes no long-term backport
commitment. Security fixes land on `main` and are included in the next
release tag.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**
Public disclosure before a fix is available puts users and the project at
risk.

### Primary channel — GitHub Private Vulnerability Reporting

Use **GitHub's built-in private vulnerability reporting** mechanism:

1. Navigate to the repository on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability** (under "Advisories").
4. Fill in the advisory form and submit.

This creates a private Security Advisory that is visible only to repository
maintainers. Maintainers must have "Private vulnerability reporting" enabled
in repository settings — if the button is absent, that setting has not yet
been activated; contact a maintainer directly via a GitHub DM or by opening
a blank issue asking them to enable it, without disclosing vulnerability
details.

There is no security email alias for this project. The GitHub private
reporting mechanism is the only supported channel.

### What to include

A useful report typically contains:

- A concise description of the class of vulnerability.
- Steps to reproduce, or a minimal reproducer if possible.
- The component, file, or interface where the issue manifests.
- Your assessment of the impact and, if relevant, the conditions required.
- Any suggested fix or mitigation, if you have one.

## Response Expectations

These are good-faith intentions appropriate to an early-stage open-source
project, not contractual SLAs.

| Stage | Target |
|---|---|
| Initial acknowledgement | Within 5 business days of receipt |
| Triage and severity assessment | Within 10 business days |
| Fix or mitigation | Depends on severity and complexity; critical issues are prioritised |
| Coordinated disclosure | Maintainers aim to coordinate a public disclosure date with the reporter before publishing a fix |

Maintainers will keep reporters informed of progress. If a report has not
been acknowledged within 5 business days, feel free to follow up in the same
advisory thread.

**Credit:** Reporters who disclose responsibly will be credited in the
Security Advisory and, at their preference, in the release notes when the
fix ships.

## Coordinated Disclosure

This project follows a coordinated (responsible) disclosure model. Reporters
are asked to:

- Avoid public disclosure until a fix has been released or a coordinated
  disclosure date has been agreed with the maintainers.
- Refrain from exploiting the vulnerability beyond what is needed to
  demonstrate it.
- Not access, modify, or delete data belonging to other users.

Maintainers will make every reasonable effort to resolve valid reports
quickly and to keep reporters informed throughout the process.

## In-Scope Vulnerability Classes

The following classes are of especially high value given that this component
is a credential custodian and authorization enforcement point. Reports in
these classes are particularly welcomed.

### Authorization bypass

The broker enforces a three-axis authorization check on every operation:
scope (`filesystem_id`) × intent (`read` / `write` / `preview`) ×
`downloadable`, derived from policy on each request and denied by default.
Any path that allows an operation to proceed without a passing three-axis
check, or that causes the resolver to return a grant when the policy
requires a deny, is in scope.

### Audit bypass or tampering

Every file-activity event must be durably committed to the OCSF audit sink
before the operation is acknowledged; a failure to write the audit record
must cause the operation to be denied (fail-closed). The audit sink maintains
a hash chain. Vulnerabilities of interest include: an operation that is
acknowledged without a durable prior audit write; a broken or forgeable hash
chain; any path that allows the audit-latch state (permanent deny after a
sink failure) to be bypassed or reset without an explicit operator action.

### Credential leak

The backend object-store credential is held exclusively by this broker; no
other component speaks the backend protocol. Any path that causes the
credential (or its derivative secrets) to appear in logs, error messages,
audit records, metrics labels, HTTP responses, or to be transmitted to a
caller other than the backend engine is in scope.

### Ceiling and limit bypass

The broker enforces ceilings on concurrent in-flight bytes, open file
descriptors, and request sizes. Any path that allows these limits to be
exceeded — causing unbounded resource consumption or enabling a
denial-of-service against the host — is in scope.

### Path and containment escape

Operations are scoped to a `filesystem_id` prefix; reads and writes must be
contained within that prefix. Any path traversal, symlink-escape, or
encoding trick that causes a read or write to access bytes outside the
authorized scope prefix is in scope.

### Storage-egress-lane bypass

Backend network traffic must transit the storage-dedicated egress lane; a
direct backend dial that bypasses the lane is a policy violation. Any
configuration path, flag, or code path that routes backend traffic outside
the dedicated lane without an explicit operator override is in scope.

## Out of Scope

The following are generally not considered security vulnerabilities for this
project:

- Missing features not yet on the implementation roadmap.
- Issues that require physical access to the host machine.
- Vulnerabilities in dependencies, unless this project exposes them in a
  security-relevant way (report those upstream first; mention them here if
  they affect the in-scope classes above).
- Denial-of-service scenarios that require valid `trusted_operator`
  credentials and a physical operator account.
