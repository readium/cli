# Readium Command Line Interface

The Readium CLI (Command Line Interface) is a multi-command utility based on the [`go-toolkit`](https://github.com/readium/go-toolkit).

It covers an extended set of use cases beyond reading, allowing authors, publishers, distributors, retailers and libraries to easily interact with publication files.

## Installation

To install `readium` in `~/go/bin`, run `make install`. Use `make build` to build the binary in the current directory.

Builds are also available directly from the [releases section](https://github.com/readium/cli/releases) of this repository.

## List of commands

| Command | Description |
| ------- | ----------- |
| [`manifest`](#the-manifest-command) | The `manifest` command can parse a publication and return a [Readium Web Publication Manifest](https://readium.org/webpub-manifest/), which is printed to `stdout`. |
| [`serve`](#the-serve-command) | The `serve` command starts an HTTPS server that can serve publications. A log is printed to `stdout`. |

## Potential additions

| Command | Description | Discussion |
| ------- | ----------- | ---------- |
| `convert` | Convert back and forth between EPUB and Readium Web Publication. | |
| `optimize` | Optimize images contained in an EPUB or a Readium Web Publication. | |
| `package` | Package images or audio files into a Readium Web Publication. | <https://github.com/readium/cli/discussions/2> |

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

### Inferring accessibility metadata

The `manifest` command can infer additional accessibility metadata when they are missing, with the `--infer-a11y` flag. 

```sh
readium manifest --infer-a11y=split publication.epub
```

It takes one of the following arguments:

| Option | Description |
| ------ |------------ |
| `no` (*default*) | No accessibility metadata will be inferred. |
| `merged` | Accessibility metadata will be inferred and merged with the authored ones in `accessibility`. |
| `split` | Accessibility metadata will be inferred but stored separately in `https://readium.org/webpub-manifest#inferredAccessibility`. |

#### List of inferred metadata

| Key | Value | Rules |
| --- | ----- | ----- |
| `accessMode` | `auditory` | If the publication contains a reference to an audio or video resource (inspect `resources` and `readingOrder` in RWPM). |
| `accessMode` | `visual` | If the publications contains a reference to an image or a video resource (inspect `resources` and `readingOrder` in RWPM). |
| `accessModeSufficient` | `textual` | If the publication is partially or fully accessible (WCAG A or above).<br>Or if the publication does not contain any image, audio or video resource (inspect "resources" and "readingOrder" in RWPM)<br>Or if the only image available can be identified as a cover. |
| `feature` | `displayTransformability` | :warning: This rule is only used with reflowable EPUB files that conform to WCAG AA or above. |
| `feature` | `pageNavigation` | If the publications contains a page list (check for the presence of a `pageList` collection in RWPM). |
| `feature` | `tableOfContents` | If the publications contains a table of contents (check for the presence of a `toc` collection in RWPM). |
| `feature` | `MathML` | If the publication contains any resource with MathML (check for the presence of the `contains` property where the value is `mathml` in `readingOrder` or `resources` in RWPM). |
| `feature` | `synchronizedAudioText` | If the publication contains any reference to Media Overlays. |

### Inspecting images

The `manifest` command can inspect images and extract additional information from them, with the `--inspect-images` flag.

```sh
readium manifest --inspect-images publication.epub
```

When using this flag, each image returned in the manifest will contain the following keys:

* `height` (in pixels)
* `width` (in pixels)
* `size` (in bytes)
* `animated` (a boolean) under `properties`
* `hash` (an array of object) under `properties`


### Ignoring images

The `manifest` command provides two different flags for ignoring images, either by:

* using a directory with the `--infer-a11y-ignore-image-dir` flag
* or a list of algorithms/hashes with the `--infer-a11y-ignore-image-hashes` flag

The `--infer-a11y-ignore-image-dir` needs the path to a directory as an argument:

```sh
readium manifest --infer-a11y=split --infer-a11y-ignore-image-dir=directory publication.epub
```

The `--infer-a11y-ignore-image-hashes` flag takes one or more hashes (in the format &lt;algorithm&gt;:&lt;base64 value&gt;) separated by commas. It will automatically detect the list of algorithms and use them to inspect images.

```sh
readium manifest --infer-a11y=split --infer-a11y-ignore-image-hashes=phash-dct:YzZTDc7IMzk=,sha256:EvaoUnJkxsWkMM0NUf4CwOZMMvEpDRKk7omCBSN67Gc= publication.epub
```

### Using different hashing algorithms

By default, this utility will default to SHA-256 when inspecting images or ignoring images from a directory. This behaviour can be overriden using the `--hash` flag to use additional or different algorithms.

* Inspecting images.

  ```sh
  readium manifest --inspect-images --hash=sha256,phash-dct publication.epub
  ```
    
* Ignoring images from a directory.

  ```sh
  readium manifest --infer-a11y=split --infer-a11y-ignore-image-dir=directory --hash=sha256,phash-dct publication.epub
  ```

It supports one or more values from the following list:

| Option | Algorithm |
| ------ | --------- |
| `sha256` (*default*) | SHA-256 |
| `md5` | MD5 |
| `phash-dct` | [pHash DCT](https://phash.org/) |
| `https://blurha.sh` | [BlurHash](https://blurha.sh) |

In addition to cryptographic hashing algorithms (such as SHA-256 and MD5), perceptual ones such as pHash-DCT are also available. They're useful for detecting similar images or an identical image in a different format, but they have a higher risk of collision than cryptographic hashes.


## The `serve` command

By default, the `serve` command will start an HTTP server listening by default on  `http://localhost:15080`, serving all compatible files (EPUB, PDF, CBZ, etc.) found in a directory as Readium Web Publications.

### Examples

* Serve files from a directory.

    ```sh
    readium serve directory
    ```

### Listing files

For debugging purposes, the server exposes a `/list.json` endpoint that
returns a list of all the publications found in the directory along with their
encoded paths. This `path` is calculated using Base64 to encode each filename.

This will be replaced by an OPDS 2.0 feed in a future release.

The Readium Web Publication Manifest of each publication is available at `http://localhost:15080/{path}/manifest.json`

### Streaming remote publications over HTTP/HTTPS

The `serve` command is also capable of streaming remote files over HTTP/HTTPS and serving them as Readium Web Publications, as long as the server supports byte range requests.

This feature is currently enabled by default, but will be moved behind a feature flag in future releases.

To stream a remote publication replace the `path` with a Base 64 encoded URL instead.

For example:

* I'd like to stream <https://github.com/IDPF/epub3-samples/releases/download/20230704/accessible_epub_3.epub>
* Which can be Base 64 encoded to `aHR0cHM6Ly9naXRodWIuY29tL0lEUEYvZXB1YjMtc2FtcGxlcy9yZWxlYXNlcy9kb3dubG9hZC8yMDIzMDcwNC9hY2Nlc3NpYmxlX2VwdWJfMy5lcHVi`
* As long as the HTTP server from the `serve` command is running, I can access the Readium Web Publication Manifest at <http://localhost:15080/aHR0cHM6Ly9naXRodWIuY29tL0lEUEYvZXB1YjMtc2FtcGxlcy9yZWxlYXNlcy9kb3dubG9hZC8yMDIzMDcwNC9hY2Nlc3NpYmxlX2VwdWJfMy5lcHVi/manifest.json>