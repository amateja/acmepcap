# Changelog

## [0.4.0] - 2026-06-11

### Added

- Added parser support for IPv6 `sipmsg.log` endpoints in `[address]:port`
  notation.
- Added oversized SIP payload protection for UDP/IPv4 and UDP/IPv6 packet
  limits, including a `--summary` counter.

### Changed

- Changed output path validation to reject symbolic links before opening the
  output file.
- Changed generated PCAP SnapLen to fit maximum-size normal IPv6 packets.

### Fixed

- Fixed IPv6 packet serialization on Python 3.9.

## [0.3.0] - 2026-05-21

### Added

- Added `--summary` to report converted and skipped record counts.

### Changed

- Changed final records without exact 40-dash delimiters to be counted as
  incomplete and skipped instead of converted.
- Changed CLI file handling to validate input and output paths before opening
  files, avoiding output creation or truncation during argument parsing.

## [0.2.0] - 2026-05-13

### Changed

- Reduced memory usage by streaming input parsing and PCAP output writing.

### Fixed

- Fixed parsing of single-digit day log entries such as `Feb  3`.
- Fixed SIP payload truncation by requiring exact 40-dash delimiter lines.
- Fixed conversion of final valid messages without trailing delimiters.
- Fixed generated SIP payload line endings to use CRLF (`\r\n`).
- Fixed timestamp inference for multi-year rollover and DST fall-back cases.
- Fixed mtime rounding compensation by reducing tolerance from 60 seconds to 1
  second.

## [0.1.0] - 2026-01-05

### Added

- Initial public release.
- Added command-line conversion from Acme Packet `sipmsg.log` files to PCAP.
- Added optional gzip-compressed output.
- Added timezone selection for interpreting SBC-local log timestamps.
- Added pure-Python PCAP, IPv4, UDP, and frame serialization.
