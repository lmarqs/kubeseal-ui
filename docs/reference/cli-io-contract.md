# CLI I/O contract

`ksui` is meant to compose with other tools, so what goes where is fixed.

## Channels

| Stream | Carries |
|---|---|
| stdout | the sealed secret, and nothing else |
| stderr | warnings, progress, validation results, and the interactive wizard |

`ksui ... > sealed.yaml` therefore yields a file containing only the manifest, and
`ksui ... 2>/dev/null` discards every diagnostic without touching the data.

When `--sealed-secret-file` (`-w`) is given, the manifest goes to that file and
stdout stays empty.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the secret was sealed |
| 1 | something failed at runtime, such as an unreachable controller |
| 2 | the command line was wrong or incomplete |
| 3 | the controller could not decrypt the sealed secret (`--validate`) |
| 130 | interrupted |

Anything the caller has to fix on the command line exits 2, including unknown
flags, an invalid secret key, a missing `--name`, and a secret with no entries.
Every such failure names what is wrong and prints a `hint:` line suggesting the
fix. Missing input is never prompted for.

## Flags shared with kubeseal

These keep kubeseal's names and meanings, so existing habits and scripts carry
over: `--cert`, `--controller-name`, `--controller-namespace`, `--scope`,
`--allow-empty-data`, `--validate`, `--from-file`, `--name`, `--kubeconfig`,
`--fetch-cert`, `-o`/`--format` (the output *format*), and
`-w`/`--sealed-secret-file` (the output *path*).

One deliberate difference: `--format` defaults to `yaml` rather than kubeseal's
`json`, because the output is usually committed to a repository.

Flags kubeseal does not define: `--ci`, `--context`, `--from-literal`, and
`-n`/`--namespace`, the last two following kubectl's naming.

## Keeping values out of shell history

`--from-literal` puts the value on the command line, where the shell records it.
To avoid that, read it from a file or pipe it in:

```sh
ksui --name db-creds --from-file password=- < /run/secrets/password
pass show db/password | ksui --name db-creds --from-file password=-
```

`-` and `/dev/stdin` both mean stdin.
