# The `serve` command

By default, the `serve` command will start an HTTP server listening by default on  `http://localhost:15080`, serving all compatible files (EPUB, PDF, CBZ, etc.) found in a directory as Readium Web Publications.

## Examples

* Serve files from a directory.

    ```sh
    readium serve directory
    ```

## Listing files

For debugging purposes, the server exposes a `/list.json` endpoint that
returns a list of all the publications found in the directory along with their
encoded paths. This `path` is calculated using Base64 to encode each filename.

This will be replaced by an OPDS 2.0 feed in a future release.

The Readium Web Publication Manifest of each publication is available at `http://localhost:15080/{path}/manifest.json`

## Streaming remote publications over HTTP/HTTPS

The `serve` command is also capable of streaming remote files over HTTP/HTTPS and serving them as Readium Web Publications, as long as the server supports byte range requests.

This feature is currently enabled by default, but will be moved behind a feature flag in future releases.

To stream a remote publication replace the `path` with a Base 64 encoded URL instead.

For example:

* I'd like to stream <https://github.com/IDPF/epub3-samples/releases/download/20230704/accessible_epub_3.epub>
* Which can be Base 64 encoded to `aHR0cHM6Ly9naXRodWIuY29tL0lEUEYvZXB1YjMtc2FtcGxlcy9yZWxlYXNlcy9kb3dubG9hZC8yMDIzMDcwNC9hY2Nlc3NpYmxlX2VwdWJfMy5lcHVi`
* As long as the HTTP server from the `serve` command is running, I can access the Readium Web Publication Manifest at <http://localhost:15080/aHR0cHM6Ly9naXRodWIuY29tL0lEUEYvZXB1YjMtc2FtcGxlcy9yZWxlYXNlcy9kb3dubG9hZC8yMDIzMDcwNC9hY2Nlc3NpYmxlX2VwdWJfMy5lcHVi/manifest.json>