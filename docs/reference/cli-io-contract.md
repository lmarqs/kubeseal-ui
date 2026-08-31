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

## Flags shared with kubeseal

These keep kubeseal's names and meanings, so existing habits and scripts carry
over: `--cert`, `--controller-name`, `--controller-namespace`, `--scope`,
`--allow-empty-data`, `--validate`, `--from-file`, `--name`, `--kubeconfig`,
`--fetch-cert`, `-o`/`--format` (the output *format*), and
`-w`/`--sealed-secret-file` (the output *path*).

One deliberate difference: `--format` defaults to `yaml` rather than kubeseal's
`json`, because the output usually ends up committed to a repository.

Flags kubeseal does not define: `--ci`, `--context`, `--from-literal`, and
`-n`/`--namespace`, the last two following kubectl's naming.

## Keeping values out of shell history

`--from-literal` puts the value on the command line, where your shell records it.
To avoid that, read it from a file or pipe it in:

```sh
ksui --name db-creds --from-file password=- < /run/secrets/password
pass show db/password | ksui --name db-creds --from-file password=-
```

Both `-` and `/dev/stdin` mean stdin.
