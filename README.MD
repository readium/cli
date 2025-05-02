# Readium Command Line Interface

The Readium CLI (Command Line Interface) is a multi-command utility based on the [`go-toolkit`](https://github.com/readium/go-toolkit).

It covers an extended set of use cases beyond reading, allowing authors, publishers, distributors, retailers and libraries to easily interact with publication files.

## Installation

To install `readium` in `~/go/bin`, run `make install`. Use `make build` to build the binary in the current directory.

Builds are also available directly from the [releases section](https://github.com/readium/cli/releases) of this repository.

## List of commands

| Command | Description |
| ------- | ----------- |
| `manifest` | The `manifest` command can parse a publication and return a Readium Web Publication Manifest (in JSON), which is printed to `stdout`. |
| `serve` | The `serve` command starts an HTTPS server that can serve publications. A log is printed to stdout. |

## The `manifest` command

### Examples

* Print out a compact JSON RWPM.
    ```sh
    readium manifest publication.epub
    ```
* Pretty-print a JSON RWPM using two-space indent.
    ```she
    readium manifest --indent "  " publication.epub
    ```
* Extract the publication title with `jq`.
    ```sh
    readium manifest publication.epub | jq -r .metadata.title
    ```

### Accessibility inferences

`readium manifest` can infer additional accessibility metadata when they are missing, with the `--infer-a11y` flag. 

```sh
readium manifest --infer-a11y=split publication.epub
```

It takes one of the following arguments:

| Option           | Description                                                                                            |
|------------------|--------------------------------------------------------------------------------------------------------|
| `no` (*default*) | No accessibility metadata will be inferred.                                                            |
| `merged`         | Accessibility metadata will be inferred and merged with the authored ones in `metadata.accessibility`. |
| `split`          | Accessibility metadata will be inferred but stored separately in `metadata.inferredAccessibility`.     |

##### Inferred metadata

| Key | Value | Inferred? |
|-----|-------|-----------|
| `accessMode` | `auditory` | If the publication contains a reference to an audio or video resource (inspect `resources` and `readingOrder` in RWPM) |
| `accessMode` | `visual` | If the publications contains a reference to an image or a video resource (inspect `resources` and `readingOrder` in RWPM) |
| `accessModeSufficient` | `textual` | If the publication is partially or fully accessible (WCAG A or above)<br>Or if the publication does not contain any image, audio or video resource (inspect "resources" and "readingOrder" in RWPM)<br>Or if the only image available can be identified as a cover |
| `feature` | `displayTransformability` | If the publication is fully accessible (WCAG AA or above)<br>:warning: This property should only be inferred for reflowable EPUB files as it doesn't apply to other formats (FXL, PDF, audiobooks, CBZ/CBR). |
| `feature` | `pageNavigation` | If the publications contains a page list (check for the presence of a `pageList` collection in RWPM) |
| `feature` | `tableOfContents` | If the publications contains a table of contents (check for the presence of a `toc` collection in RWPM) |
| `feature` | `MathML` | If the publication contains any resource with MathML (check for the presence of the `contains` property where the value is `mathml` in `readingOrder` or `resources` in RWPM) |
| `feature` | `synchronizedAudioText` | If the publication contains any reference to Media Overlays |

### Inspecting images

`readium manifest` can inspect images and extract additional information from them, with the `--inspect-images` flag.

```sh
readium manifest --inspect-images publication.epub
```

When using this flag, each image returned in the manifest will contain the following keys:

* `height` (in pixels)
* `width` (in pixels)
* `size` (in bytes)
* `animated` (a boolean) under `properties`
* `hash` (an array of object) under `properties`

By default, both SHA-256 and MD5 hashes are calculated for each image, but this behaviour can be overriden using the `--hash` flag with one of the following values:

| Option | Algorithm |
| ------ | --------- |
| `sha256` | SHA-256 |
| `md5` | MD5 |
| `phash-dct` | [pHash DCT](https://phash.org/) |
| `https://blurha.sh` | [BlurHash](https://blurha.sh) |
