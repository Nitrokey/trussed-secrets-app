#![cfg_attr(not(test), no_std)]
#![warn(

// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    non_ascii_idents,
    trivial_casts,
    unused,
    unused_qualifications,
    clippy::expect_used,
    clippy::unwrap_used
)]
#![deny(unsafe_code)]

//! Secrets App is a secrets manager, focused on OTP and Password Safe features.
//!
//! It additionally supports Yubikey's HMAC challenge (for KeepassXC),
//! and Reverse HOTP (for use with Heas for the measured boot).
//! It is based on oath-authenticator, extended and reworked.

#[macro_use]
extern crate delog;
generate_macros!();

#[macro_use(hex)]
extern crate hex_literal;

/// This is the main module, containing the Secrets App implementation.
pub mod authenticator;

pub use authenticator::{Authenticator, Options};
use core::time::Duration;
mod calculate;
mod command;
pub use command::Command;
mod credential;
#[cfg(feature = "ctaphid")]
mod ctaphid;
mod oath;
mod state;

/// This is the application id, which allows to select and identify it
pub const YUBICO_OATH_AID: &[u8] = &hex!("A000000527 2101");

/// This constant defines timeout for the regular UP confirmation
pub const UP_TIMEOUT_MILLISECONDS: u32 = 15 * 1000;

/// The default ID for the PIN auth backend
pub const BACKEND_USER_PIN_ID: u8 = 0;

/// The default value of the PIN attempt counter
pub const ATTEMPT_COUNTER_DEFAULT_RETRIES: u8 = 8;

/// Do not make longer messages than this size
pub const CTAPHID_MESSAGE_SIZE_LIMIT: usize = 3072;

/// Deny Reverse HOTP request, if required time from the last failed verification attempt has not passed yet
/// Makes brute-force attack slower.
pub const REQUIRED_DELAY_ON_FAILED_VERIFICATION: Duration = Duration::from_secs(5);

// class AID(bytes, Enum):
//     OTP = b'\xa0\x00\x00\x05\x27 \x20\x01'
//     MGR = b'\xa0\x00\x00\x05\x27\x47\x11\x17'
//     OPGP = b'\xd2\x76\x00\x01\x24\x01'
//     OATH = b'\xa0\x00\x00\x05\x27 \x21\x01'
//     PIV = b'\xa0\x00\x00\x03\x08'
//     U2F = b'\xa0\x00\x00\x06\x47\x2f\x00\x01'  # Official
//     U2F_YUBICO = b'\xa0\x00\x00\x05\x27\x10\x02'  # Yubico - No longer used

fn ensure<T>(cond: bool, err: T) -> core::result::Result<(), T> {
    match cond {
        true => Ok(()),
        false => Err(err),
    }
}
type Result<T = ()> = iso7816::Result<T>;
