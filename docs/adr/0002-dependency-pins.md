# 2. Dependency pins for sealed-secrets and the Charm stack

Date: 2026-08-31

## Status

Accepted

## Context

The two dependency families this project rests on — sealed-secrets and the Charm TUI
stack — each carry constraints that could conflict. Before building features on top
of them, a single build was used to confirm they coexist.

Findings from that build:

- The sealed-secrets Go module was renamed. Releases up to v0.37.0 declare
  `github.com/bitnami-labs/sealed-secrets`; v0.38.0 and later declare
  `github.com/bitnami/sealed-secrets`. Only the new path resolves for current
  versions.
- sealed-secrets v0.39.1 requires Go >= 1.26.7 and builds against Kubernetes
  libraries at v0.36.x.
- `clientcmd.ClientConfig` structurally satisfies `kubeseal.ClientConfig`, so the
  deferred-loading client configuration can be handed to the sealing functions
  directly.
- `huh` v1.0.0 requires the Bubble Tea v1 line, and compiles cleanly against
  `bubbles` v1.0.0 despite pinning an earlier pseudo-version itself.
- The resulting binary is roughly 35 MB, dominated by client-go.

## Decision

Pin:

- `github.com/bitnami/sealed-secrets` at v0.39.1
- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go` at v0.36.3, matching what
  sealed-secrets builds against, rather than the newest release
- `github.com/charmbracelet/bubbletea` on the v1 line, with `huh` v1.0.0,
  `bubbles` v1.0.0 and `lipgloss` v1.1.0
- the Go toolchain at 1.26.7 via `mise.toml`

## Consequences

- Upgrading sealed-secrets means re-checking the Kubernetes library pins and the Go
  toolchain floor together.
- Bubble Tea v2 is deliberately out of scope while `huh` requires v1.
- Kubernetes libraries are held one minor version behind their latest release on
  purpose; the pin exists to match sealed-secrets, not because newer versions are
  known to break.
