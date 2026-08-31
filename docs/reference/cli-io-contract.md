# CLI I/O contract

`ksui` composes with other tools, so what goes where does not change.

## Channels

| Stream | Carries |
|---|---|
| stdout | the data you asked for: the sealed secret, the certificate `--fetch-cert` prints, or the build information from `ksui version` |
| stderr | warnings, progress, validation results, and the interactive wizard |

So `ksui ... > sealed.yaml` gives you a file holding only the manifest, and
`ksui ... 2>/dev/null` throws away every diagnostic while leaving the data alone.

Pass `--sealed-secret-file` (`-w`) and the manifest goes to that file instead.
stdout then stays empty. `ksui merge` rewrites the file it was given, so its
stdout stays empty too.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the secret was sealed, or the wizard was left without sealing anything |
| 1 | something failed at runtime, such as an unreachable controller |
| 2 | the command line was wrong or incomplete |
| 3 | the controller could not decrypt the sealed secret (`--validate`) |
| 130 | a signal arrived while an operation was in flight and cancelled it |

Anything you have to fix on the command line exits 2: an unknown flag, an invalid
secret key, a missing `--name`, a secret with no entries. Each of those says what
is wrong and prints a `hint:` line with the fix.

## When ksui asks and when it does not

Flags that already describe a secret are taken as given and sealed. The wizard
appears only when something is left to ask *and* there is a terminal to ask it
on: stderr and stdin both have to be terminals, `--ci` must not be passed, and
`CI` must not be set in the environment. Fail any of those and missing input is a
usage error instead, so scripted runs never block on a prompt.

## Validation

`--validate` seals first, then asks the controller whether it can decrypt the
result. Exit 3 means it could not.

It needs a controller to ask, so it is skipped — with a warning on stderr and
exit 0 — when `--cert` supplied the certificate, or when the controller could not
be reached and a cached certificate stood in for it. A run that exits 0 has
therefore not necessarily been validated; the warning is what tells the two
apart.

## Flags shared with kubeseal

These keep kubeseal's names and meanings, so existing habits and scripts carry
over: `--cert`, `--controller-name`, `--controller-namespace`, `--scope`,
`--allow-empty-data`, `--validate`, `--kubeconfig`, `--fetch-cert`,
`-o`/`--format` (the output *format*), and `-w`/`--sealed-secret-file` (the
output *path*).

One deliberate difference: `--format` defaults to `yaml` rather than kubeseal's
`json`, because the output usually ends up committed to a repository.

`--name` and `--from-file` keep kubeseal's spelling and syntax without its
restriction: kubeseal accepts both only alongside `--raw`, and `ksui` has no
equivalent of `--raw`.

Flags kubeseal does not define: `--ci` and `--from-literal`.

`--context` and `-n`/`--namespace` exist in both, spelled the way kubectl spells
them, but they do not mean the same thing. kubeseal binds them as kubeconfig
overrides. In `ksui`, `--context` still picks the kubeconfig context, while
`--namespace` names the namespace the secret is sealed for — the one the strict
and namespace-wide scopes are bound to. Left out, it falls back to the namespace
the active context declares.

## Keeping values out of shell history

`--from-literal` puts the value on the command line, where your shell records it.
To avoid that, read it from a file or pipe it in:

```sh
ksui --name db-creds --from-file password=- < /run/secrets/password
pass show db/password | ksui --name db-creds --from-file password=-
```

Both `-` and `/dev/stdin` mean stdin. Only one key may be read from it, since a
second would silently get nothing; asking twice exits 2.

## Merging

`ksui merge <file>` takes a narrower set of flags, because the file supplies the
name, namespace, type and sealing scope: `--from-literal` and `--from-file` add
or replace keys, `--remove` drops them, and all three are repeatable. At least
one is required, and a merge that would leave the file with no keys at all exits
2.

`--format` here defaults to neither `yaml` nor `json`. Left out, the file keeps
the shape it already has.
