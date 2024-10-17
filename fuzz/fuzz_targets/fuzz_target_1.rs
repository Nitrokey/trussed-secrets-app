#![no_main]

// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// #![feature(iter_advance_by)]

use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Vec<&[u8]> {
    // Parse incoming data into slices from format:
    // Size N (1 bytes)
    // Value (N bytes)

    let mut res = Vec::with_capacity(100);
    if data.len() < 2 || data.len() > 1024 * 1024 {
        // Too big or too small data found at this point. Skip it.
        return vec![];
    }

    let mut data = data;
    loop {
        if 2 >= data.len() {
            break;
        }
        let (size, rest) = data.split_at(1);
        data = rest;

        let size = size[0] as usize;
        if size >= data.len() {
            break;
        }
        let (v, rest) = data.split_at(size);
        data = rest;
        res.push(v);
    }
    res
}

use trussed::types::Location;
mod virt;

fuzz_target!(|data: &[u8]| {
    virt::with_ram_client("secrets", move |client| {
        let options =
            secrets_app::Options::new(Location::Internal, 0, 1, [0x42, 0x42, 0x42, 0x42], u16::MAX);
        let mut secrets = secrets_app::Authenticator::new(client, options);

        let mut response = heapless::Vec::<u8, { 3 * 1024 }>::new();

        let commands = parse(data);
        for data in commands {
            if let Ok(command) = iso7816::command::CommandView::try_from(data) {
                response.clear();
                secrets.respond(command, &mut response).ok();
            }
        }
    })
});
