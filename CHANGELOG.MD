# Changelog

All notable changes to this project will be documented in this file.

**Warning:** Features marked as *alpha* may change or be removed in a future release without notice. Use with caution.

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