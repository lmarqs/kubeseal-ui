# CLI I/O contract

`ksui` composes with other tools, so what goes where does not change.

## Channels

| Stream | Carries |
|---|---|
| stdout | the sealed secret, and nothing else |
| stderr | warnings, progress, validation results, and the interactive wizard |

So `ksui ... > sealed.yaml` gives you a file holding only the manifest, and
`ksui ... 2>/dev/null` throws away every diagnostic while leaving the data alone.

Pass `--sealed-secret-file` (`-w`) and the manifest goes to that file instead.
stdout then stays empty.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the secret was sealed |
| 1 | something failed at runtime, such as an unreachable controller |
| 2 | the command line was wrong or incomplete |
| 3 | the controller could not decrypt the sealed secret (`--validate`) |
| 130 | interrupted |

Anything you have to fix on the command line exits 2: an unknown flag, an invalid
secret key, a missing `--name`, a secret with no entries. Each of those says what
is wrong and prints a `hint:` line with the fix. `ksui` never prompts for input it
is missing.

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
