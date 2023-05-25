#![no_std]

// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[macro_use]
extern crate delog;
generate_macros!();

mod container;
mod error;

pub type EncryptedDataContainer = container::EncryptedDataContainer;
pub type Error = error::Error;
pub type Result<T = ()> = error::Result<T>;
