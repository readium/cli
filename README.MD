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

## Examples

```sh
readium manifest --infer-a11y=split moby-dick.epub | jq .metadata
```

```json
{
  "author": {
    "name": "Herman Melville",
    "sortAs": "MELVILLE, HERMAN"
  },
  "conformsTo": "https://readium.org/webpub-manifest/profiles/epub",
  "contributor": {
    "name": "Dave Cramer",
    "role": "mrk"
  },
  "http://creativecommons.org/ns#attributionURL": "http://code.google.com/p/epub-samples/",
  "http://purl.org/dc/terms/rights": "This work is shared with the public using the Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) license.",
  "http://www.idpf.org/2007/opf#version": "3.0",
  "https://github.com/readium/go-toolkit/releases": "v0.10.1",
  "https://readium.org/webpub-manifest#inferredAccessibility": {
    "accessMode": [
      "visual"
    ],
    "feature": [
      "tableOfContents"
    ]
  },
  "identifier": "code.google.com.epub-samples.moby-dick-basic",
  "language": "en-US",
  "modified": "2012-01-18T12:47:00Z",
  "layout": "reflowable",
  "publisher": "Harper & Brothers, Publishers",
  "title": "Moby-Dick"
}
```
