# Changelog

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
