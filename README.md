<!--
Copyright (C) 2023 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Secrets App

A Trussed app to manage OTP and Password Safe features of Nitrokey 3.

Based on [oath-authenticator][], an implementation of
reverse-engineered specification of Yubico's [OATH application][yubico-oath].

[trussed]: https://trussed.dev

[oath-authenticator]: https://github.com/trussed-dev/oath-authenticator

[yubico-oath]: https://developers.yubico.com/OATH/YKOATH_Protocol.html

### Current Features

Secrets App supports the following features:

- HOTP implementation - [RFC4226];
- TOTP implementation - [RFC6238];
- Reverse HOTP implementation - [the original client][hotp-verif];
- Yubikey's HMAC-SHA1 challenge for KeepassXC - [KeepassXC documentation][keepass-docs];
- Password Safe;
- A PIN with attempts counter;
- PIN-based encryption per credential;
- Touch-button protected use per credential.

The pynitrokey library can be used to communicate with this application over CTAPHID, and nitropy provides the CLI using
it. See [ctaphid.md](docs/ctaphid.md) for the details.

CCID transport is also available, and while not supported in the mentioned library yet, it can be potentially used by
the protocol-compatible applications, like the mentioned KeepassXC.

See [design.md](docs/design.md) for the UX design choices.

[RFC4226]: https://www.rfc-editor.org/rfc/rfc4226

[RFC6238]: https://www.rfc-editor.org/rfc/rfc6238

[hotp-verif]: https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code
[keepass-docs]: https://keepassxc.org/docs/
[hmac-tutorial]: https://docs.yubikey.wiki/tutorials/keepassxc

#### OTP

OTP support works reasonably well, with the following remarks:

1. Shared secret key length can be 320 bits (40 bytes) or longer.
2. HOTP implementation allows using only 32 bit counter for the initialization as of now.
3. Usage confirmation through the touch button gesture (aka UP confirmation) can be set during the credential
   registration.
4. Additional protection in a means of PIN-based encryption can be additionally set up.

#### Reverse HOTP

Reverse HOTP is an operation that allows to verify the HOTP code coming from a PC host, and shows visually to user, that
the code is correct or not, with a green or red LED respectively.
Does not need authorization by design, so the process would be automatically executed during the boot, without any
additional user intervention when possible.

This is used for the Measured Boot feature provided by Heads, which in turn is used in Nitrokey Nitropads. With
that, the Nitrokey 3 could be used in place of the sold until now Nitrokey Pro and Nitrokey Storage.

See the original description at:

- https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code

Solution contains means to avoid desynchronization between the host's and device's counters. Device calculates up to 9
values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10 subsequent
counter positions). In case:

- no code would match - the on-device counter will not be changed;
- incoming code parsing would fail - the on-device counter will not be changed;
- code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched
  code-generated HOTP counter and incremented by 1;
- code would match, and the code matches counter without offset - the counter will be incremented by 1;
- the HOTP counter overflows while searching for the matching code - error is returned, and counter is not changed.

Device will stop verifying the HOTP codes, when the difference between the host and on-device counters will be greater
or equal to 9.

Credentials registered to use with this operation cannot be used with regular HOTP calls by design.

#### Password Safe
A Password Safe credential can store login, password and additional information, each having maximum 128 bytes.
Credentials can be encrypted and/or require touch button press before reading.

#### KeepassXC support With HMAC-SHA1
KeepassXC is supported through the Yubikey's HMAC-SHA1 challenge commands. Both slots are supported. What's more, any number of credentials can be created of this kind to support other HMAC-SHA1 applications.
There is no other support for Yubikey commands planned, nor tested. In fact, the authorization method used by Yubikey is removed, which will probably make it not working with the clients supporting this protocol.

#### CTAPHID Extension

This implementation uses CTAPHID to transfer commands to the Secrets App application. This transport is used to
improve compatibility on platforms, where the default transport for this application, CCID, is not easily available (
e.g. due to being taken by other services, or requiring Administrator
privileges). A CTAPHID vendor command number was selected to use (`0x70`), thus allowing for a compatible extension of
any FIDO compliant device.

See [CTAPHID](docs/ctaphid.md) for the further documentation regarding the NLnet funded CTAPHID extension.

### Further work

While most of the features needed for the daily use are implemented, there are still some tasks to do:

- proper LED blinking for the Reverse HOTP feature - since the upstream framework does not handle any LED animations
  yet, the failing and successful cases can be distinguished only by the blinking length at the moment (10 seconds for
  the pass, 1000 for the failed case). There is no support for the animation priority in the upstream framework as well,
  hence any other operation can overwrite the animation.

Tasks and features still discussed to be done:

- extend HOTP feature to handle 64-bit counter - right now only 32-bit value is supported to stay compatible with the
  original protocol, however this should be easily extended by introducing a new TLV tag, which would mark the wider
  value;
- support SHA512 if that would be ever needed.

### Development

See [design](docs/design.md) document to see decisions taken to make the solution cohesive.

Use `dangerous_disable_encryption` Rust flag to disable data encryption for the debug purposes. E.g.:

```text
$ env RUSTFLAGS="--cfg dangerous_disable_encryption" cargo test
```

### License

<sup>`oath-authenticator` is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.</sup>
<br>
<sub>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.</sub>

## Funding

[<img src="https://nlnet.nl/logo/banner.svg" width="200" alt="Logo NLnet: abstract logo of four people seen from above" hspace="20">](https://nlnet.nl/)
[<img src="https://nlnet.nl/image/logos/NGI0PET_tag.svg" width="200" alt="Logo NGI Zero: letterlogo shaped like a tag" hspace="20">](https://nlnet.nl/NGI0/)

Changes in this project were funded through the [NGI0 PET](https://nlnet.nl/PET) Fund, a fund established
by [NLnet](https://nlnet.nl/) with financial support from the European
Commission's [Next Generation Internet programme](https://ngi.eu/), under the aegis of DG Communications Networks,
Content and Technology under grant agreement No 825310.
