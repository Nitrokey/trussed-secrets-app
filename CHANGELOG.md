# Changelog

## [0.11.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.11.0) (2023-05-30)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.11.0-rc2...0.11.0)

**Implemented enhancements:**

- Add challenge-response support for KeepassXC [\#61](https://github.com/Nitrokey/trussed-secrets-app/issues/61)
- Add Password Safe [\#60](https://github.com/Nitrokey/trussed-secrets-app/issues/60)
- Extend compiler and clippy lints [\#39](https://github.com/Nitrokey/trussed-secrets-app/issues/39)
- Extend Credential structure with Password Safe field [\#63](https://github.com/Nitrokey/trussed-secrets-app/pull/63) ([szszszsz](https://github.com/szszszsz))

**Closed issues:**

- Use released version for trussed-auth [\#58](https://github.com/Nitrokey/trussed-secrets-app/issues/58)
- Group attributes in Command::Credential per kind [\#66](https://github.com/Nitrokey/trussed-secrets-app/issues/66)
- Add config option for the maximum number of credentials [\#62](https://github.com/Nitrokey/trussed-secrets-app/issues/62)
- Finalize renaming to `secrets-app` [\#47](https://github.com/Nitrokey/trussed-secrets-app/issues/47)
- Resetting strategy [\#43](https://github.com/Nitrokey/trussed-secrets-app/issues/43)

**Merged pull requests:**

- Match trussed\* dependencies to the used in NK3 v1.4.0 [\#80](https://github.com/Nitrokey/trussed-secrets-app/pull/80) ([szszszsz](https://github.com/szszszsz))
- Ignore errors on factory reset, and start with the persistent storage [\#79](https://github.com/Nitrokey/trussed-secrets-app/pull/79) ([szszszsz](https://github.com/szszszsz))

## [0.11.0-rc2](https://github.com/nitrokey/trussed-secrets-app/tree/0.11.0-rc2) (2023-05-30)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.11.0-rc1...0.11.0-rc2)

**Implemented enhancements:**

- Reuse compliance [\#77](https://github.com/Nitrokey/trussed-secrets-app/issues/77)

**Closed issues:**

- Migrate bit manipulation to bitflags crate [\#78](https://github.com/Nitrokey/trussed-secrets-app/issues/78)
- Resetting strategy [\#43](https://github.com/Nitrokey/trussed-secrets-app/issues/43)
- Use cfg switch for no-encryption feature [\#23](https://github.com/Nitrokey/trussed-secrets-app/issues/23)

**Merged pull requests:**

- Replace feature with a config switch for the debug mode [\#84](https://github.com/Nitrokey/trussed-secrets-app/pull/84) ([szszszsz](https://github.com/szszszsz))
- Migrate list properties byte to bitflags [\#82](https://github.com/Nitrokey/trussed-secrets-app/pull/82) ([szszszsz](https://github.com/szszszsz))
- Add copyright and spdx identifiers [\#81](https://github.com/Nitrokey/trussed-secrets-app/pull/81) ([szszszsz](https://github.com/szszszsz))
- Match trussed\* dependencies to the used in NK3 v1.4.0 [\#80](https://github.com/Nitrokey/trussed-secrets-app/pull/80) ([szszszsz](https://github.com/szszszsz))
- Ignore errors on factory reset, and start with the persistent storage [\#79](https://github.com/Nitrokey/trussed-secrets-app/pull/79) ([szszszsz](https://github.com/szszszsz))

## [0.11.0-rc1](https://github.com/nitrokey/trussed-secrets-app/tree/0.11.0-rc1) (2023-05-25)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.10.0...0.11.0-rc1)

**Implemented enhancements:**

- Add information about static password to List [\#68](https://github.com/Nitrokey/trussed-secrets-app/issues/68)
- Add challenge-response support for KeepassXC [\#61](https://github.com/Nitrokey/trussed-secrets-app/issues/61)
- Add Password Safe [\#60](https://github.com/Nitrokey/trussed-secrets-app/issues/60)
- Return serial number [\#50](https://github.com/Nitrokey/trussed-secrets-app/issues/50)
- Extend compiler and clippy lints [\#39](https://github.com/Nitrokey/trussed-secrets-app/issues/39)
- Add challenge-response method for KeepassXC support [\#64](https://github.com/Nitrokey/trussed-secrets-app/pull/64) ([szszszsz](https://github.com/szszszsz))
- Extend Credential structure with Password Safe field [\#63](https://github.com/Nitrokey/trussed-secrets-app/pull/63) ([szszszsz](https://github.com/szszszsz))

**Closed issues:**

- Group attributes in Command::Credential per kind [\#66](https://github.com/Nitrokey/trussed-secrets-app/issues/66)
- Add config option for the maximum number of credentials [\#62](https://github.com/Nitrokey/trussed-secrets-app/issues/62)
- Finalize renaming to `secrets-app` [\#47](https://github.com/Nitrokey/trussed-secrets-app/issues/47)

## [0.10.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.10.0) (2023-04-26)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.9.0...0.10.0)

**Implemented enhancements:**

- Do not require PIN for OTP credentials at all [\#48](https://github.com/Nitrokey/trussed-secrets-app/issues/48)
- Reverse HOTP: introduce delay on the failure to fight brute-force attack [\#13](https://github.com/Nitrokey/trussed-secrets-app/issues/13)
- Update blinking handlers [\#4](https://github.com/Nitrokey/trussed-secrets-app/issues/4)
- PIN-less credentials access with hardware key encryption [\#53](https://github.com/Nitrokey/trussed-secrets-app/pull/53) ([szszszsz](https://github.com/szszszsz))
- Handle status changes [\#51](https://github.com/Nitrokey/trussed-secrets-app/pull/51) ([szszszsz](https://github.com/szszszsz))

**Closed issues:**

- Release v0.10 [\#59](https://github.com/Nitrokey/trussed-secrets-app/issues/59)

**Merged pull requests:**

- Use cbor\_smol instead of trussed re-exports [\#54](https://github.com/Nitrokey/trussed-secrets-app/pull/54) ([robin-nitrokey](https://github.com/robin-nitrokey))

## [0.9.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.9.0) (2023-04-05)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.8.0...0.9.0)

**Merged pull requests:**

- Bump trussed-auth [\#49](https://github.com/Nitrokey/trussed-secrets-app/pull/49) ([sosthene-nitrokey](https://github.com/sosthene-nitrokey))

## [0.8.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.8.0) (2023-03-08)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.7.0...0.8.0)

**Merged pull requests:**

- Add encryption of TOTP secret [\#46](https://github.com/Nitrokey/trussed-secrets-app/pull/46) ([sosthene-nitrokey](https://github.com/sosthene-nitrokey))
- Quick corrections and backend debugging [\#45](https://github.com/Nitrokey/trussed-secrets-app/pull/45) ([szszszsz](https://github.com/szszszsz))

## [0.7.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.7.0) (2023-03-03)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.6.0...0.7.0)

**Implemented enhancements:**

- PIN-based encryption [\#37](https://github.com/Nitrokey/trussed-secrets-app/issues/37)
- PIN verification as an alternative to the VALIDATE command [\#6](https://github.com/Nitrokey/trussed-secrets-app/issues/6)
- Add PIN-based encryption [\#41](https://github.com/Nitrokey/trussed-secrets-app/pull/41) ([szszszsz](https://github.com/szszszsz))

**Fixed bugs:**

- Application hangs after update from 0.3.0 to 0.6.0 if not reset [\#38](https://github.com/Nitrokey/trussed-secrets-app/issues/38)
- Ignore the deserialization error, and use default state instead [\#40](https://github.com/Nitrokey/trussed-secrets-app/pull/40) ([szszszsz](https://github.com/szszszsz))

**Merged pull requests:**

- Remove alloc crate [\#42](https://github.com/Nitrokey/trussed-secrets-app/pull/42) ([robin-nitrokey](https://github.com/robin-nitrokey))

## [0.6.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.6.0) (2023-02-24)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.5.0...0.6.0)

**Merged pull requests:**

- Make encrypted\_container no\_std [\#36](https://github.com/Nitrokey/trussed-secrets-app/pull/36) ([robin-nitrokey](https://github.com/robin-nitrokey))
- Make storage location configurable [\#35](https://github.com/Nitrokey/trussed-secrets-app/pull/35) ([robin-nitrokey](https://github.com/robin-nitrokey))
- CI: add ref to the exact commit for pc-usbip-runner [\#33](https://github.com/Nitrokey/trussed-secrets-app/pull/33) ([szszszsz](https://github.com/szszszsz))
- Bump dependencies [\#32](https://github.com/Nitrokey/trussed-secrets-app/pull/32) ([robin-nitrokey](https://github.com/robin-nitrokey))

## [0.5.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.5.0) (2023-02-03)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.4.0...0.5.0)

**Implemented enhancements:**

- Prevent encrypted credentials switching [\#22](https://github.com/Nitrokey/trussed-secrets-app/issues/22)
- Use CBOR for state serialization [\#17](https://github.com/Nitrokey/trussed-secrets-app/issues/17)
- Add example [\#7](https://github.com/Nitrokey/trussed-secrets-app/issues/7)
- Multipacket handling for credentials listing and other improvements [\#24](https://github.com/Nitrokey/trussed-secrets-app/pull/24) ([szszszsz](https://github.com/szszszsz))
- Credentials Encryption [\#16](https://github.com/Nitrokey/trussed-secrets-app/pull/16) ([szszszsz](https://github.com/szszszsz))

**Fixed bugs:**

- Write state only if changed [\#19](https://github.com/Nitrokey/trussed-secrets-app/issues/19)
- State loading can crash [\#14](https://github.com/Nitrokey/trussed-secrets-app/issues/14)

**Closed issues:**

- Correct CBOR serialization of the credentials [\#21](https://github.com/Nitrokey/trussed-secrets-app/issues/21)
- Correct encapsulation [\#20](https://github.com/Nitrokey/trussed-secrets-app/issues/20)

**Merged pull requests:**

- Test CI [\#18](https://github.com/Nitrokey/trussed-secrets-app/pull/18) ([szszszsz](https://github.com/szszszsz))

## [0.4.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.4.0) (2022-12-06)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.3.1...0.4.0)

**Implemented enhancements:**

- Check UP on important operations [\#9](https://github.com/Nitrokey/trussed-secrets-app/issues/9)
- Return status code bytes [\#3](https://github.com/Nitrokey/trussed-secrets-app/issues/3)
- Further fuzzing efforts and returning error codes [\#15](https://github.com/Nitrokey/trussed-secrets-app/pull/15) ([szszszsz](https://github.com/szszszsz))

## [0.3.1](https://github.com/nitrokey/trussed-secrets-app/tree/0.3.1) (2022-12-01)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.3.0...0.3.1)

**Implemented enhancements:**

- Stability improvements [\#8](https://github.com/Nitrokey/trussed-secrets-app/issues/8)
- Initial fuzzing support and fixes [\#11](https://github.com/Nitrokey/trussed-secrets-app/pull/11) ([szszszsz](https://github.com/szszszsz))

**Closed issues:**

- Update documentation [\#12](https://github.com/Nitrokey/trussed-secrets-app/issues/12)
- Handle parsing errors [\#5](https://github.com/Nitrokey/trussed-secrets-app/issues/5)

## [0.3.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.3.0) (2022-11-18)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/0.2.0...0.3.0)

**Merged pull requests:**

- Support CTAPHID transport [\#2](https://github.com/Nitrokey/trussed-secrets-app/pull/2) ([szszszsz](https://github.com/szszszsz))

## [0.2.0](https://github.com/nitrokey/trussed-secrets-app/tree/0.2.0) (2022-10-27)

[Full Changelog](https://github.com/nitrokey/trussed-secrets-app/compare/9c3008986d3e1462f260d40d53e56f2005476a08...0.2.0)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
