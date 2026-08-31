# 1. Seal in-process instead of shelling out to kubeseal

Date: 2026-08-31

## Status

Accepted

## Context

Creating a SealedSecret means encrypting a Kubernetes Secret with the public key
of a sealed-secrets controller. The reference implementation is the `kubeseal`
CLI. A wrapper can either shell out to that binary or import the same Go packages
it uses.

Shelling out guarantees identical behaviour with whatever `kubeseal` version a
user already has. It also makes the binary useless wherever `kubeseal` is absent,
and it forces us to read CLI output to tell apart the failures we need to react
to: an unreachable controller, an RBAC denial, a secret the controller cannot
decrypt.

## Decision

Import `github.com/bitnami/sealed-secrets` and seal in-process.

Secrets are built as `corev1.Secret` values in memory and encrypted with the same
code the `kubeseal` CLI runs, so sealing scope annotations and template
propagation behave the same way.
[ADR 4](0004-sealing-entry-point.md) records which entry point into that code we
ended up calling, and why.

## Consequences

- `ksui` is one self-contained binary with nothing to install alongside it.
- Failures arrive as Go values, so the wizard can respond to each one differently
  instead of matching strings.
- We inherit the sealed-secrets module's Kubernetes dependency versions and its
  minimum Go toolchain, and have to track both when upgrading.
- Sealing is unit-testable with no cluster: generate an RSA key, seal, then
  decrypt with `pkg/crypto` and compare.
