# Changelog

All notable changes to this project will be documented in this file.

**Warning:** Features marked as *alpha* may change or be removed in a future release without notice. Use with caution.

## [0.9.1] - 2026-07-23

### Changed

- Docker builds use a local `mime.types` and pinned container hash for better security

### Fixed

- Fixed `session:` scheme URLs for the web server not passing on query parameters to the session's HTTP request. Session URLs like `session:https://example.com/data.json?t=abc` will work now
- Hash list for manifest command is now validated
- This has probably never shown up in the real world, but requesting the byte range `bytes=0-0` for a resource would have caused issues in the web server
- Further confine local FS reads on Windows. The long term solution is to is os.Root or such, but that requires go-toolkit changes
- Improved bonding reliability to deal with edge cases
- Improved open publication cache logic to deal with rare edge cases

## [0.9.0] - 2026-07-09

### Added

- Standalone Readium Web Publication Manifests (e.g. a bare `manifest.json`, `.audiobook` or `.divina` file) can now be served. The publication's resources are resolved relative to the manifest's location, whether it lives on the local file system or on a remote source (http(s), s3, gs), and absolute HTTP(S) links in a manifest are fetched as-is. Previously, trying to open one would fail
- Added the `--audio-parsing-cache-retain` flag (enabled by default): the data fetched while parsing a remote audiobook (the container header and embedded chapter titles) is kept in memory, and requests for those byte ranges are served from it. Browsers request exactly these ranges before starting playback of e.g. an M4B, so with a many-chapter audiobook on a remote source, playback now starts several times faster. Disable the flag to save memory (it costs roughly one cache block per chapter plus the file headers, so a few MB per audiobook). Or just use a better audio format...
- Publications opened from a WebPub manifest now get a positions service, and a guided navigation service (MVP) when they contain HTML content

### Changed

- The go-toolkit has been updated to v0.15.1. Together with changes to the webserver, this dramatically reduces the latency and excess data transfer of streaming publications from remote (http(s), s3, gs) sources. For the detailed list, refer to the [go-toolkit's changelog](https://github.com/readium/go-toolkit/blob/develop/CHANGELOG.md); the highlights as they apply to the CLI:
  - The webserver now streams remote media to the client as it arrives whenever the range can be fetched efficiently (bare files and uncompressed archive entries), instead of buffering the entire requested range in memory first. Time to first byte no longer depends on the size of the requested range, memory use is bounded, and a client disconnecting cancels the remote transfer
  - Streaming has been optimized to unlock the ability for data transfers from a local filesystem source to the network to happen in-kernel with `sendfile`
  - Seeking through media inside a remote archive no longer re-downloads parts of the archive over and over (in the worst case, the whole archive tail on every request), and data is fetched in far fewer, larger range requests
  - Opening the same publication only queries the remote source for a file's size once, instead of once per request while streaming. For audiobooks in particular, this removes a remote round trip from every range request a browser makes
  - Fixed ranged reads of S3 resources downloading the entire object
  - Fixed a path traversal issue: a crafted link inside a publication could address content outside the publication's own location (e.g. a sibling S3 key or URL path) on the remote source it is served from

### Fixed

- Clients disconnecting over HTTP/2 mid-response (e.g. a browser aborting range requests while probing or seeking media, which is routine) were logged as streaming errors such as `http2: stream closed`, polluting the logs. They are now ignored like their HTTP/1 counterparts (broken pipe, connection reset)

## [0.8.0] - 2026-06-06

### Added

- Added the `--audio-embedded-chapters`, `--audio-parsing-concurrency`, `--audio-parsing-cache-block-size` flags for more control over audiobook parsing with regards to speed/latency/memory tradeoffs

### Changed

- The go-toolkit has been updated to v0.14.0. This adds improved audiobook parsing. For a more detailed list of changed, refer to the [go-toolkit's changelog](https://github.com/readium/go-toolkit/blob/develop/CHANGELOG.md#0140---2026-06-06). While best effort is made to minimize the latency when reading audiobooks from remote sources, there can still be an excess of reads that are necessary to fully parse metadata. The new settings provide a way to make tradeoffs depending on the situation

## [0.7.1] - 2026-05-18

### Fixed

- v0.7.0 was tagged to the wrong commit, this is otherwise identical to v0.7.0 in terms of changes.

## [0.7.0] - 2026-05-18

### Changed

- Updated dependencies
- HTTP requests made by `serve` now have a better, more descriptive `User-Agent` header

### Added

- A new `session` URL scheme has been added to `serve`, which allows for retrieval of a Reading Session API document. This is an experimental way of having a JSON object located at a remote URL (http, https) that returns the ebook's real location URL, as well as metadata to override, and rights (limitations) on the session. If you're trying to enforce restrictions seriously, you should use this together with one of the bonding modes below
- Two new modes have been added to `serve`, `jwt-bonding` and `jwks-bonding`. The difference between the two mirrots the `jwt` and `jwks` modes. Bonding (which must be combined with the Reading Session API) lets you more strongly tie a reading session (reader URL) to a web browser, through the use of a device cookie and a bonding JWT. Be sure to check out the new params available to tweak settings for sessions/bonding
- The webserver now strives to return [problem details in JSON](https://datatracker.ietf.org/doc/html/rfc9457), which should helps clients better understand what the cause of an error is
- A CORS setting (`--cors-allowed-origin`) is available for `serve`, for setups requiring CORS
- An HTTP authorization setting (`--http-host-authorization`) has been added, which will let you add the `authorization` header to specific hosts you're making requests to. This should help authenticate the reader for the Reading Session API endpoint (or whatever other needs you have like auth for your ebook storage domain)
- H2C (plaintext http2) support has been added to the webserver, for reverse proxies that support it

## [0.6.6] - 2026-03-09

### Fixed

- Updated the go-toolkit, which fixes a race condition (error) that could occur reading local files

### Changed

- Now, OPUS files has the mimetype `audio/opus` in manifests, but remain `audio/ogg; codecs=opus` in webserver responses for better compatibility

## [0.6.5] - 2026-02-28

### Fixed

- Updated the go-toolkit, which fixes incorrect checking of whether a publication conforms to a specific profile based on its contents. This may have caused mistaken cases of a11y inferrence or Divina/Audiobook/EPUB/PDF profile detection in manifest outputs

## [0.6.4] - 2026-02-26

### Fixed

- The go-toolkit has been updated, which fixes [not being able to retrieve resources at paths containing special characters](https://github.com/readium/cli/issues/94), such as spaces. This applies to any archived as well as exploded publications which contained such files. Retrieval of local files also had a bug

### Changed

- Go and third-party dependencies updated

## [0.6.3] - 2025-12-08

### Changed

- The go-toolkit has been updated, and the version key present in WebPub manifests has changed from `https://github.com/readium/go-toolkit/releases` to `https://github.com/readium/go-toolkit#version`. This was done to reduce confusion as go-toolkit releases have been superseeded by cli releases

## [0.6.2] - 2025-12-04

### Fixed

- Problems with [remote streaming of compressed multimedia](https://github.com/readium/cli/issues/27) have been addressed. This was due to a combination a bug in the implementation of partial resource reading, as well as special logic to make the kinds of requests browsers send for audio/video stream lead to smaller reads of the original resource. It's better just not to compressed multimedia in an EPUB though
- This update also fixes the issues with image inspection (failure to decode images) that occured due the bug in the partial resource reading, which was triggered by image decoding libraries reading fragments of the image files

### Changed

- Go and third-party dependencies updated

## [0.6.1] - 2025-11-03

### Fixed

- Docker container build fixed

## [0.6.0] - 2025-11-03

### Added

- When using the serve command, a new `-m` flag allows for authenticated access to publications using a JWT in the route to the publication instead of the encoded path. The subject (`sub`) of the JWT will instead be used as the path to the publication. The first new mode is `jwt` mode, which uses the HS256 method of authentication and a shared secret that is either provided using `--jwt-shared-secret` or autogenerated at startup. The second mode, `jwks`, is combined with the `--jwks-url` flag that points to JWKS file, which can contain multiple keys used to validate the JWT, allowing for key rotation and other algorithms using public/private keypairs
- The path of a publication with no resource specified now redirects to the manifest file

### Changed

- The GOAMD64 value for release builds has been changed from `v3` to `v2`. The discussion regarding this is [here](https://github.com/readium/cli/issues/78). This allows execution of the built binaries on older x64 CPUs
- The HTTP client configuration used for streaming of remote publications has been changed to require, at minimum, TLSv1.2 for HTTPS connections
- The serve command's routes are now prefixed with `/webpub`. So `<domain>/<path>/manifest.json` is now `<domain>/webpub/<path>/manifest.json`
- Go and third-party dependencies updated

### Removed

- The `/list.json` route in the serve command's webserver has been removed. It is not compatible with the new authenticated access schemes, and was only intended to be temporary. It may be replaced in the future by an OPDS2 feed

## [0.5.1] - 2025-10-14

### Fixed

- When a manifest has no links (such as when using the `manifest` command), the `links` property is now omitted instead of set to `null` in the JSON output
- The `--infer-page-count` works again, and general issues with services in the `manifest` command have been fixed due to a revamp in how they work in the toolkit

### Changed

- Go and third-party dependencies updated

## [0.5.0] - 2025-09-19

### Added

- The `--http-host-whitelist` flag has been added to the serve command, to which a list of hosts can be passed. If at least one host is passed, access to streamed HTTP/HTTPS publications will be restricted to the provided hosts. A host like example.com can be further restricted to a "folder", such as example.com/the/path/
- The `--http-unsafe-requests` flag has been added. It disabled restrictions that are enabled by default to prevent access to private IP addresses (such as internal infrastructure or localhost), and should be used with caution

### Fixed

- The software version displayed when using the `--version` command was incorrect due to a bug. Thanks @tefkah for the fix

### Changed

- Dependencies were updated

## [0.4.0] - 2025-07-30

### Changed

The WebPub data the go-toolkit parses and provides has been updated to more closely match the latest WebPub spec. Pay close attention to these changes if you depend on the WebPub output in reading systems/libraries that use an older version of the spec!

## [0.3.0] - 2025-07-12

### Changed

- Major changes to `readium serve` [command syntax](https://github.com/readium/cli/blob/develop/docs/serve.md), to improve ease of use
- Docker container no longer includes any test publications, an only enables http/https publication serving by default
- Improvements to documentation
- Updates to dependencies

### Fixed

- Links to services (positions list etc.) are removed from the manifest when running `readium manifest`

## [0.2.1] - 2025-06-08

### Added

- Add `--s3-use-path-style` flag to enable broader support for S3-like services that use the deprecated path-style bucket access (especially useful in docker environments)

### Fixed

- The version output from the CLI was incorrect, consisting of the go-toolkit version. [It is now](https://github.com/readium/cli/pull/32) a combination of the CLI and go-toolkit version

## [0.2.0] - 2025-05-21

### Added

- Add `--infer-a11y-ignore-image-hashes` and `--infer-a11y-ignore-image-dir` flags to `manifest` command to ignore certain images when inferring a publication's a11y access mode

### Changed

- Upgraded go-toolkit from v0.9.0 to v0.10.1
- Default hashing algorithms for inspected images changed from SHA-256 + MD5 to just SHA-256

## [0.1.0] - 2025-04-30

### Added

- Created this project based on the command-line utilities from the [https://github.com/readium/go-toolkit](Go Toolkit)