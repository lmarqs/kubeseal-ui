# 3. Package layout

Date: 2026-08-31

## Status

Accepted

## Context

The tool holds three kinds of code: what it is for, how it reaches the outside
world, and how it is run. Keeping them apart is what lets the sealing logic be
tested without a cluster and the wizard without a terminal.

## Decision

Packages are named for what they are about rather than for the role they play, and
each falls into one of the three kinds:

| Package | Kind | Holds |
|---|---|---|
| `internal/secret` | reason | secret keys, names, entries, and building a `corev1.Secret` |
| `internal/seal` | reason | sealing, sealing scope, which controller to seal for, obtaining certificates |
| `internal/kube` | connection | kubeconfig, namespaces, controller discovery, applying manifests |
| `internal/version` | connection | build metadata stamped in at link time |
| `internal/wizard` | how it is run | the interactive terminal flow: one screen per question, and a stack that makes going back possible |
| `cmd/ksui` | how it is run | flags, the I/O contract, wiring the above together |

Dependencies point toward the reason. `internal/kube` depends on `internal/seal`
for the `Controller` type; nothing in `internal/seal` or `internal/secret` depends
on `internal/kube`. `cmd/ksui` depends on all of them and is the only place that
picks which implementations get used.

`internal/wizard` drives the sealing logic rather than containing it, and reaches
a cluster only through the interfaces in its `ports.go`, which `cmd/ksui`
satisfies with the `internal/kube` and `internal/seal` types.

`Controller` lives with the sealing logic rather than with the Kubernetes code
because which controller a secret is sealed for is a property of the secret: each
controller holds its own key pair, so the choice decides whether the result can
ever be decrypted. Finding a controller's Service is a Kubernetes lookup, and that
stays in `internal/kube`.

## Consequences

- `internal/secret` and `internal/seal` are tested with no cluster and no
  terminal. Most of what can go wrong in this tool lives in those two packages.
- `internal/kube` is tested against a fake clientset, RBAC denials included.
- Two trade-offs here are deliberate:
  - `internal/seal` does I/O of its own: reading a certificate from a file or URL,
    fetching one from a controller, and caching it on disk. Rather than split the
    package, `Resolver.Fetch` is a function the caller can replace, which is how
    the policy that chooses between cache, controller and file gets tested without
    touching a disk or a network.
  - `cmd/ksui` holds some orchestration, such as working out which namespace to
    use and deciding when validation is possible at all. The wizard needs the same
    decisions; once it grows them, that orchestration moves into `internal/seal`
    instead of being written twice.
