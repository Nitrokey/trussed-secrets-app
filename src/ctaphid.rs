// Copyright (C) 2021-2022 The Trussed Developers
// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{authenticator::Client, Authenticator};
use ctaphid_app::{App, Command as HidCommand, Error, VendorCommand};
use heapless_bytes::Bytes;
use iso7816::Status;
use trussed_core::InterruptFlag;
pub const OTP_CCID: VendorCommand = VendorCommand::H70;

impl<T: Client, const N: usize> App<'static, N> for Authenticator<T> {
    fn commands(&self) -> &'static [HidCommand] {
        &[HidCommand::Vendor(OTP_CCID)]
    }

    fn call(
        &mut self,
        command: HidCommand,
        input_data: &[u8],
        response: &mut Bytes<N>,
    ) -> Result<(), Error> {
        match command {
            HidCommand::Vendor(OTP_CCID) => {
                let arr: [u8; 2] = Status::Success.into();
                response.extend(arr);
                let ctap_to_iso7816_command = iso7816::command::CommandView::try_from(input_data)
                    .map_err(|_e| {
                    response.clear();
                    info_now!("ISO conversion error: {:?}", _e);
                    Error::InvalidLength
                })?;
                let res = self.respond(ctap_to_iso7816_command, response);

                match res {
                    Ok(_) => return Ok(()),
                    Err(Status::MoreAvailable(b)) => {
                        response[0] = 0x61;
                        response[1] = b;
                        return Ok(());
                    }
                    Err(e) => {
                        info_now!("OTP command execution error: {:?}", e);
                        let arr: [u8; 2] = e.into();
                        response.clear();
                        response.extend(arr);
                    }
                }
            }
            _ => {
                return Err(Error::InvalidCommand);
            }
        }
        Ok(())
    }
    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        self.trussed.interrupt()
    }
}
