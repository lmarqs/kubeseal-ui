# 1. Seal in-process instead of shelling out to kubeseal

Date: 2026-08-31

## Status

Accepted

## Context

Creating a SealedSecret requires encrypting a Kubernetes Secret with the public key
of a sealed-secrets controller. The reference implementation is the `kubeseal` CLI.
A wrapper could either shell out to that binary or import the same Go packages it
uses.

Shelling out guarantees byte-identical behaviour with whatever `kubeseal` version a
user already has, but it makes the binary useless where `kubeseal` is absent, and it
forces us to parse CLI output to distinguish failure modes we need to react to
(controller unreachable, RBAC denied, validation failed).

## Decision

Import `github.com/bitnami/sealed-secrets/pkg/kubeseal` and seal in-process.

Secrets are built as `corev1.Secret` values and passed to `kubeseal.Seal`, the same
entry point the `kubeseal` CLI uses, so sealing scope annotations and template
propagation behave identically. `kubeseal.EncryptSecretItem` is reserved for
replacing individual keys when merging into an existing file.

## Consequences

- `ksui` is a single self-contained binary with no external runtime dependency.
- Errors arrive as Go values, so the wizard can react to each failure mode precisely.
- We inherit the sealed-secrets module's Kubernetes dependency versions and its
  minimum Go toolchain, and must track them when upgrading.
- Sealing logic is unit-testable without a cluster: generate an RSA key, seal, and
  decrypt with `pkg/crypto`.
