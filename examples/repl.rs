use gdb_protocol::{io::GdbServer, packet::{CheckedPacket, Kind}, Error};
use std::io::{self, prelude::*};

fn main() -> Result<(), Error> {
    println!("Listening on port 1337...");
    let mut server = GdbServer::listen("0.0.0.0:1337")?;
    println!("Connected!");

    while let Some(packet) = server.next_packet()? {
        println!(
            "-> {:?} {:?}",
            packet.kind,
            std::str::from_utf8(&packet.data)
        );

        print!(": ");
        io::stdout().flush()?;
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if response.ends_with('\n') {
            response.truncate(response.len() - 1);
        }
        let response = CheckedPacket::from_data(Kind::Packet, response.into_bytes());

        let mut bytes = Vec::new();
        response.encode(&mut bytes).unwrap();
        println!("<- {:?}", std::str::from_utf8(&bytes));

        server.dispatch(&response)?;
    }

    println!("EOF");
    Ok(())
}
