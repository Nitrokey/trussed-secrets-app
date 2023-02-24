#![no_std]

#[macro_use]
extern crate delog;
generate_macros!();

mod container;
mod error;

pub type EncryptedDataContainer = container::EncryptedDataContainer;
pub type Error = error::Error;
pub type Result<T = ()> = error::Result<T>;
