# kubeseal-ui

A friendly terminal wizard for creating [Bitnami SealedSecrets](https://github.com/bitnami/sealed-secrets).

The binary is called `ksui`. It asks which cluster and namespace you are targeting,
what to name the secret, then collects the secret values one at a time — letting you
list, edit and remove entries before anything is sealed. Once sealed it can validate
that the controller is able to decrypt the result, apply it, or write out the YAML.

Sealing happens **in-process** using the sealed-secrets Go module, so the `kubeseal`
binary is not required.

## Status

Early development. The tooling, CLI skeleton and release pipeline are in place; the
wizard, sealing and apply flows are landing milestone by milestone.

## Install

Download a binary from the [releases page](https://github.com/lmarqs/kubeseal-ui/releases),
or build from source:

```sh
go build -o ksui ./cmd/ksui
```

## Usage

```sh
ksui            # run the wizard
ksui version    # print build information
```

The wizard renders on stderr and writes the sealed secret to stdout, so redirection
works the way you would expect:

```sh
ksui > my-secret.yaml
```

## Development

The project uses [mise](https://mise.jdx.dev) to pin its toolchain and expose tasks:

```sh
mise install       # install Go, golangci-lint, goreleaser, node
mise run build     # build ./ksui
mise run test      # unit tests with race detection
mise run check     # go vet, golangci-lint, goreleaser check
mise run fmt       # format sources and tidy go.mod
```

## License

MIT
