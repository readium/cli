# The `serve` command

The `serve` command is designed to stream and parse packaged publications and serve them as [Web Publications](https://readium.org/webpub-manifest) over HTTP/HTTPS.

## Serving files from a directory

By default, this command will serve publications available in a given directory from the filesystem.

Since there's no default path, it requires the presence of a `--file-directory` flag and a path.

### Example

* Serving files from a directory.

    ```sh
    readium serve --file-directory ./publications
    ```

### Listing files

For debugging purposes, the server exposes a `/list.json` endpoint that
returns a list of all the publications found in the directory along with their
encoded paths.

This will be replaced by an OPDS 2.0 feed in a future release, using an optional flag.

## Using S3 or a compatible API

Many services provide an S3 compatible API. The `serve` command is fully compatible with these API, allowing implementers to stream and serve publications stored in multiple buckets.

### Example

* Streaming files from an S3 compatible API.

    ```sh
    readium serve -s s3 --s3-endpoint https://example.com/endpoint --s3-access-key {access-key} --s3-secret-key {secret-key}
    ```
    
### Required flags

| Flag | Description |
| ---- | ----------- |
| `--s3-endpoint` | URL for the S3 service |
| `--s3-access-key` | Access Key for the S3 service |
| `--s3-secret-key` | Secret Key for the S3 service |

### Optional flags

| Flag | Description |
| ---- | ----------- |
| `--s3-region` | Region for the S3 service. Defaults to `auto`. |

## Using GCS

In addition to S3, the `serve` command also supports GCS (Google Cloud Storage).

Unlike S3, support for GCS relies on configuration handled through [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) rather than flags when calling the Readium CLI. If running this project in e.g. [Google Cloud Run](https://cloud.google.com/run), the credentials will be automatically loaded.

### Example

* Streaming files from GCS.

    ```sh
    readium serve -s gs
    ```

## Streaming over HTTP/HTTPS

The `serve` command is also capable of streaming remote files over HTTP/HTTPS as long as the remote server supports byte range requests.

### Example

* Streaming files over HTTP and HTTPS.

    ```sh
    readium serve -s http,https
    ```

This feature is currently enabled by default, but will be moved behind a feature flag in future releases.

## Supporting multiple schemes

As illustrated in the previous sections of this document, configuration for the `serve` commands relies primarily on a `-s`/`--scheme` flag that supports a list of comma separated values:

| Scheme | Value |
| ------ | ----- |
| Filesystem | `file` |
| HTTP | `http` |
| HTTPS | `https` |
| S3 | `s3` |
| Google Cloud Storage | `gs` |

### Example

* Serving files from both GCS and HTTPS.

    ```sh
    readium serve -s gs,https
    ```

## Binding an address and a port

By default, the `serve` commands starts an HTTP server on `localhost` using `15080` as a port.

These settings can be overriden using dedicated flags:

| Flag | Description |
| ---- | ----------- |
| `-a` or `--address` | Address of the HTTP server. |
| `-p` or `--port` | Port of the HTTP server. |


## Fetching a manifest for a publication

In its current version, the `serve` command relies on a single path from which all manifests can be fetched: `/{base64url-encoded-path-to-file}/manifest.json`.

Each scheme supports a dedicated URI scheme:

| Scheme | URI scheme | Path |
| ------ | ---------- | ---- |
| Filesystem | `file://` | Path to a given file relative to the path provided in `--file-directory`.
| HTTP | `http://` | URL |
| HTTPS | `https://` | URL |
| S3 | `s3://` | Path to a bucket, followed by a path to a file (key) in that bucket: `s3://{bucket}/{path-to-file}` |
| Google Cloud Storage | `gs://` | Path to a bucket, followed by a path to a file (key) in that bucket: `gs://{bucket}/{path-to-file}` |

Once calculated, the URI scheme and path to the file have to be [base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5) encoded in order to generate a path to a manifest.

### Example

```sh
  readium serve -s gs,https
```

* I'd like to stream <https://github.com/IDPF/epub3-samples/releases/download/20230704/accessible_epub_3.epub>
* Which can be base64url encoded to `aHR0cHM6Ly9naXRodWIuY29tL0lEUEYvZXB1YjMtc2FtcGxlcy9yZWxlYXNlcy9kb3dubG9hZC8yMDIzMDcwNC9hY2Nlc3NpYmxlX2VwdWJfMy5lcHVi`
* The manifest for that file can be accessed at <http://localhost:15080/aHR0cHM6Ly9naXRodWIuY29tL0lEUEYvZXB1YjMtc2FtcGxlcy9yZWxlYXNlcy9kb3dubG9hZC8yMDIzMDcwNC9hY2Nlc3NpYmxlX2VwdWJfMy5lcHVi/manifest.json>

## Additional services

In addition to the Readium Web Publication Manifest, this commands also provides additional services that can be discovered through the `links` in each manifest.

In its current version, the CLI provides the following services:

* [Position List](https://github.com/readium/architecture/tree/master/models/locators/positions)
* Content Iterator

We expect to deprecate the Content Iterator service in the near future.