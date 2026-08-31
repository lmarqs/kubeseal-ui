# kubeseal-ui

A friendly terminal tool for creating [Bitnami SealedSecrets](https://github.com/bitnami/sealed-secrets).

The binary is called `ksui`. It seals in-process using the sealed-secrets Go
module, so you do not need the `kubeseal` binary.

## Status

The wizard creates generic, image pull and TLS secrets. The flags create generic
ones. `ksui` can also check a sealed secret against the controller, apply it, and
change files you already have.

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

It asks which cluster and namespace, what kind of secret this is, what it is
called and how it should be scoped. Then it collects the values one at a time.
You can type a value, read it from a file, or enter it over several lines. Values
stay masked: the list shows the key, where the value came from and how large it
is, and nothing else. `esc` goes back — to the question before it on the same
screen, then to any earlier question — and keeps the entries you have already
given.

Image pull secrets ask for a registry and credentials instead. TLS secrets ask
for a certificate and a key, and `ksui` checks that the two match before it seals
anything.

Once sealed, you see the whole manifest. From there you can check that the
controller can decrypt it, apply it to the cluster, save it, or print it.
Applying tells you which keys it would add, replace and remove before it touches
the cluster.

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
ksui --name db-creds -n payments --from-file password=./password.txt
pass show db/password | ksui --name db-creds -n payments --from-file password=-
```

Secrets built from flags are `type: Opaque`. Image pull and TLS secrets — and the
check that a certificate and its key belong together — come from the wizard.

Check that the controller can actually decrypt the result before committing it:

```sh
ksui --name db-creds -n payments --from-literal a=b --validate
```

Seal with no cluster access at all, using a certificate you saved earlier:

```sh
ksui --fetch-cert > controller.pem          # once, while you have access
ksui --cert controller.pem --name db-creds -n payments --from-literal a=b
```

### Changing a sealed secret you already have

You cannot read a sealed value back, but you can give a key a new value or drop
it:

```sh
ksui merge db-creds-sealed.yaml                          # walk through the keys
ksui merge db-creds-sealed.yaml --from-literal DB_PASSWORD=rotated --remove OLD_TOKEN
```

The file keeps its name, namespace and scope. Changing any of them would make the
values already in it unreadable.

`ksui` writes the file back from the SealedSecret it read, so comments and any
fields that are not part of a SealedSecret do not survive.

### Sealing scope

By default a sealed secret is bound to both its namespace and its name, so
renaming or moving it stops the controller decrypting it. `--scope namespace-wide`
binds it to the namespace only, and `--scope cluster-wide` to neither.

### Certificates

`ksui` caches the controller's certificate under your user cache directory, keyed
by cluster and by controller, so a cluster running several controllers never
seals against the wrong key pair. It reuses a cached certificate for an hour. If
it cannot reach the controller, it falls back to the cached copy and warns you.

For the channels, exit codes and flag compatibility, see
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

[docs](docs/README.md) indexes the reference material and the ADRs that record the
design decisions.

## License

MIT
