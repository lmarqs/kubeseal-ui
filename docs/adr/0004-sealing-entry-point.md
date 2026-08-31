# 4. Seal through NewSealedSecret rather than kubeseal.Seal

Date: 2026-08-31

## Status

Accepted

## Context

The sealed-secrets module offers two ways in. `kubeseal.Seal` is what the kubeseal
CLI calls: it reads Secrets from an `io.Reader`, applies scope annotations, strips
server-side metadata, checks for empty data, and writes the result to an
`io.Writer`. It delegates the encryption itself to
`ssv1alpha1.NewSealedSecret`.

Going through `kubeseal.Seal` would mean serialising the `corev1.Secret` we just
built only for it to be parsed straight back, and it consults
`ClientConfig.Namespace()` for any scope other than cluster-wide. That last point
matters: it ties sealing to a readable kubeconfig even when a certificate file was
supplied and no cluster is involved at all.

## Decision

Call `ssv1alpha1.NewSealedSecret` directly, applying the sealing scope with
`ssv1alpha1.UpdateScopeAnnotations` first because the scope determines the
encryption label.

The concerns `kubeseal.Seal` adds on top are handled where they belong:

- scope annotations: applied before encrypting, as above
- stripping server-side metadata: unnecessary, since the Secret is built in memory
  and never came from an API server
- rejecting empty data: `secret.Build` reports it, overridable with
  `--allow-empty-data`
- serialisation: `internal/seal` encodes with the same codecs and group version
  kubeseal uses, so the output is interchangeable

`kubeseal.OpenCert`, `kubeseal.ParseKey`, `kubeseal.ValidateSealedSecret` and
`kubeseal.ParseFromFile` are used as they are.

## Consequences

- Sealing with `--cert` needs no kubeconfig, no cluster and no network.
- The encryption path is identical to kubeseal's, because it is the same function.
- Tests confirm the resulting scope semantics rather than assuming them: a
  strictly scoped secret stops decrypting when renamed, a namespace-wide one does
  not, and a cluster-wide one survives moving namespace.
- If a future sealed-secrets release changes behaviour inside `kubeseal.Seal` but
  not in `NewSealedSecret`, we will not inherit it, so upgrades should be read with
  that in mind.
