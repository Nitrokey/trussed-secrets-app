// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    #[clap(short, long)]
    file_name: String,
}

// TODO: extract parse function
fn parse(data: &[u8]) -> Vec<&[u8]> {
    // Parse incoming data into slices from format:
    // Size N (1 bytes)
    // Value (N bytes)

    let mut res = Vec::new();
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

use std::fs;

fn main() -> Result<(), ()> {
    pretty_env_logger::init();
    let args = Args::parse();

    trussed::virt::with_ram_client("secrets", move |client| {
        let mut secrets = secrets_app::Authenticator::<_>::new(client);
        let mut response = heapless::Vec::<u8, { 3 * 1024 }>::new();

        // let data = fs::read_to_string(args.file_name).unwrap();
        let data = fs::read(args.file_name).unwrap();

        let commands = parse(data.as_ref());
        for data in commands {
            if let Ok(command) = iso7816::Command::<{ 10 * 255 }>::try_from(data) {
                if let Ok(cmd) = secrets_app::Command::try_from(&command) {
                    println!(">>> {:?}", cmd);
                } else {
                    println!(">>> (unparsed) {:?}", command);
                }

                response.clear();
                let res = secrets.respond(&command, &mut response);
                println!("<<< {:?} {:?}", res, response);
            }
        }
    });
    Ok(())
}
