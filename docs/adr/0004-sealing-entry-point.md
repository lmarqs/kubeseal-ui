# 4. Seal through NewSealedSecret rather than kubeseal.Seal

Date: 2026-08-31

## Status

Accepted

## Context

The sealed-secrets module offers two ways in. `kubeseal.Seal` is what the kubeseal
CLI calls: it reads Secrets from an `io.Reader`, applies scope annotations, strips
server-side metadata, checks for empty data, and writes the result to an
`io.Writer`. The encryption itself it hands to `ssv1alpha1.NewSealedSecret`.

Going through `kubeseal.Seal` would mean serialising the `corev1.Secret` we just
built only for it to be parsed straight back. It also consults
`ClientConfig.Namespace()` for any scope other than cluster-wide, which ties
sealing to a readable kubeconfig even when you supplied a certificate file and no
cluster is involved at all.

## Decision

Call `ssv1alpha1.NewSealedSecret` directly, applying the sealing scope with
`ssv1alpha1.UpdateScopeAnnotations` first, because the scope determines the
encryption label.

`kubeseal.Seal` adds four concerns on top of that call. Each is dealt with
elsewhere:

- scope annotations, applied before encrypting, as above
- stripping server-side metadata, which is unnecessary because the Secret is built
  in memory and never came from an API server
- rejecting empty data, which `secret.Build` reports and `--allow-empty-data`
  overrides
- serialisation, which `internal/seal` does with the same codecs and group version
  kubeseal uses, so the output is interchangeable with it

Merging into an existing file takes the same route, for the same reason and one
more: `kubeseal.SealMergingInto` assigns into `spec.template` maps it does not
create, so it panics on a file whose template carries no annotations.

`kubeseal.OpenCert`, `kubeseal.ParseKey`, `kubeseal.ValidateSealedSecret` and
`kubeseal.ParseFromFile` are used as they are.

## Consequences

- Sealing with `--cert` needs no kubeconfig, no cluster and no network.
- The encryption path is identical to kubeseal's, because it is the same function.
- Tests check the resulting scope semantics rather than assuming them: a strictly
  scoped secret stops decrypting once renamed, a namespace-wide one does not, and
  a cluster-wide one survives moving to another namespace.
- A future sealed-secrets release could change behaviour inside `kubeseal.Seal`
  without touching `NewSealedSecret`, and we would not inherit it. Read release
  notes for changes in either when upgrading.
