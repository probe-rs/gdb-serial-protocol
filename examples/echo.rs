use gdb_protocol::{
    io::GdbServer,
    packet::CheckedPacket,
    Error,
};

fn main() -> Result<(), Error> {
    println!("Listening on port 1337...");
    let mut server = GdbServer::listen("0.0.0.0:1337")?;
    println!("Connected!");

    let response = CheckedPacket::empty();
    let mut bytes = Vec::new();
    response.encode(&mut bytes).unwrap();

    while let Some(packet) = server.next_packet()? {
        println!("-> {:?} {:?}", packet.kind, std::str::from_utf8(&packet.data));
        println!("<- {:?}", std::str::from_utf8(&bytes));
        server.dispatch(&response)?;
    }

    println!("EOF");
    Ok(())
}
