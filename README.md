# kubeseal-ui

A friendly terminal tool for creating [Bitnami SealedSecrets](https://github.com/bitnami/sealed-secrets).

The binary is called `ksui`. Sealing happens **in-process** using the sealed-secrets
Go module, so the `kubeseal` binary is not required.

## Status

Working for Opaque secrets, interactively and from the command line. Still to
come: guided flows for docker-registry and TLS secrets, and merging new values
into an existing sealed secret file.

## Install

Download a binary from the [releases page](https://github.com/lmarqs/kubeseal-ui/releases),
or build from source:

```sh
go build -o ksui ./cmd/ksui
```

## Usage

Run it with no arguments to be walked through the questions:

```sh
ksui
```

It asks which cluster and namespace, what the secret is called and how it should
be scoped, then collects the values one at a time — each of which can be typed,
read from a file, or entered over several lines. Values are masked and listed only
by key, where they came from and how large they are. `esc` goes back to any earlier
question without losing the entries already given.

Once sealed, the manifest is shown in full and you can check that the controller
can decrypt it, apply it to the cluster, save it, or print it.

### From the command line

Seal a secret against the controller in the current cluster:

```sh
ksui --name db-creds --namespace payments --from-literal DB_PASSWORD=hunter2
```

The manifest goes to stdout and everything else to stderr, so redirection works
the way you would expect:

```sh
ksui --name db-creds -n payments --from-literal DB_PASSWORD=hunter2 > db-creds.yaml
```

Read a value from a file, or pipe it in to keep it out of your shell history:

```sh
ksui --name tls -n web --from-file tls.crt=./cert.pem --from-file tls.key=./key.pem
pass show db/password | ksui --name db-creds -n payments --from-file password=-
```

Check that the controller can actually decrypt the result before committing it:

```sh
ksui --name db-creds -n payments --from-literal a=b --validate
```

Seal with no cluster access at all, using a certificate you saved earlier:

```sh
ksui --fetch-cert > controller.pem          # once, while you have access
ksui --cert controller.pem --name db-creds -n payments --from-literal a=b
```

### Sealing scope

By default a sealed secret is bound to both its namespace and its name, so
renaming or moving it stops the controller decrypting it. `--scope namespace-wide`
binds it to the namespace only, and `--scope cluster-wide` to neither.

### Certificates

The controller's certificate is cached under your user cache directory, keyed by
cluster and by controller, so a cluster running several controllers never seals
against the wrong key pair. A cached certificate is reused for an hour. If the
controller cannot be reached, the cached copy is used and a warning says so.

Full details of channels, exit codes and flag compatibility are in
[docs/reference/cli-io-contract.md](docs/reference/cli-io-contract.md).

## Development

The project uses [mise](https://mise.jdx.dev) to pin its toolchain and expose tasks:

```sh
mise install       # install Go, golangci-lint, goreleaser, node
mise run build     # build ./ksui
mise run test      # unit tests with race detection
mise run check     # go vet, golangci-lint, goreleaser check
mise run fmt       # format sources and tidy go.mod
```

Design decisions are recorded in [docs/adr](docs/adr).

## License

MIT
