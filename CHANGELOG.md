# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Add retry mechanism for some rare issues.

## [2.4.1] - 2025-02-25

### Changed

- Upgrade to grisp "2.8.0"

## [2.4.0] - 2024-07-29

- Add grisp_cryptoauth_tls, an helper to generate TLS options for connecting
to servers with client certificate authentication driven by grisp_cryptoauth
configuration

- Add EMULATE_CRYPTOAUTH macro that could be defined for grisp_cryptoauth to
be used in tests and in local shell.

## [2.3.0] - 2024-06-27

- Add sign_fun/3 to support OTP 27 new key option for secure Elements

## [2.2.0] - 2024-06-25

- Bump grisp to 2.5.0
- Add ssl patch file for 26 and 26.2

## [2.1.0] - 2024-01-19

- Bump grisp to 2.4.0
- Add SSL patches for OTP-24 and OTP-25

## [2.0.1] - 2023-02-15

- Hex package fix
- Use sensible default for cert templates
- Bump grisp

## [2.0.0] - 2022-02-01

- Initial release

[Unreleased]: https://github.com/grisp/grisp_cryptoauth/compare/2.4.1...HEAD
[2.4.1]: https://github.com/grisp/grisp_cryptoauth/compare/2.4.0...2.4.1
[2.4.0]: https://github.com/grisp/grisp_cryptoauth/compare/2.3.0...2.4.0
[2.3.0]: https://github.com/grisp/grisp_cryptoauth/compare/2.2.0...2.3.0
[2.2.0]: https://github.com/grisp/grisp_cryptoauth/compare/2.1.0...2.2.0
[2.1.0]: https://github.com/grisp/grisp_cryptoauth/compare/2.0.1...2.1.0
[2.0.1]: https://github.com/grisp/grisp_cryptoauth/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/grisp/grisp_cryptoauth/compare/35942fd38f38c6c118930cbc0bc77e95a11710cb...2.0.0
