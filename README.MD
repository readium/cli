# Readium Command Line Interface

The Readium CLI (Command Line Interface) is a multi-command utility based on the [`go-toolkit`](https://github.com/readium/go-toolkit).

It covers an extended set of use cases beyond reading, allowing authors, publishers, distributors, retailers and libraries to easily interact with publication files.

## Installation

Multiplatform builds are available directly from the [releases section](https://github.com/readium/cli/releases) of this repository.

As an alternative, to install `readium` in `~/go/bin`, run `make install`. Use `make build` to build the binary in the current directory.

## List of commands

| Command | Description |
| ------- | ----------- |
| [`manifest`](./docs/manifest.md) | The `manifest` command can parse a publication and return a [Readium Web Publication Manifest](https://readium.org/webpub-manifest/), which is printed to `stdout`. |
| [`serve`](./docs/serve.md) | The `serve` command starts an HTTPS server that can serve publications. A log is printed to `stdout`. |

## Potential additions

| Command | Description | Discussion |
| ------- | ----------- | ---------- |
| `convert` | Convert back and forth between EPUB and Readium Web Publication. | |
| `optimize` | Optimize images contained in an EPUB or a Readium Web Publication. | |
| `package` | Package images or audio files into a Readium Web Publication. | <https://github.com/readium/cli/discussions/2> |