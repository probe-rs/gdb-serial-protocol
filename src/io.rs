use crate::{
    packet::{CheckedPacket, Kind},
    parser::Parser,
    Error,
};

use std::{
    io::{prelude::*, BufReader},
    mem,
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

pub const BUF_SIZE: usize = 8 * 1024;

pub struct GdbServer<R, W>
where
    R: BufRead,
    W: Write,
{
    pub reader: R,
    pub writer: W,
    parser: Parser,
}

impl GdbServer<BufReader<TcpStream>, TcpStream> {
    pub fn listen<A>(addr: A) -> Result<Self, Error>
        where A: ToSocketAddrs
    {
        let listener = TcpListener::bind(addr)?;

        let (writer, _addr) = listener.accept()?;
        let reader = BufReader::new(writer.try_clone()?);

        Ok(Self::new(reader, writer))
    }
}
impl<'a> GdbServer<&'a mut &'a [u8], Vec<u8>> {
    pub fn tester(input: &'a mut &'a [u8]) -> Self {
        Self::new(input, Vec::new())
    }
    pub fn response(&mut self) -> Vec<u8> {
        mem::replace(&mut self.writer, Vec::new())
    }
}
impl<R, W> GdbServer<R, W>
where
    R: BufRead,
    W: Write,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            parser: Parser::default(),
        }
    }

    pub fn next_packet(&mut self) -> Result<Option<CheckedPacket>, Error> {
        loop {
            let buf = self.reader.fill_buf()?;
            if buf.is_empty() {
                break Ok(None);
            }

            let (read, packet) = self.parser.feed(buf)?;
            self.reader.consume(read);

            if let Some(packet) = packet {
                break Ok(match packet.kind {
                    Kind::Packet => match packet.check() {
                        Some(checked) => {
                            self.writer.write_all(&[b'+'])?;
                            Some(checked)
                        },
                        None => {
                            self.writer.write_all(&[b'-'])?;
                            continue; // Retry
                        }
                    },
                    // Protocol specifies notifications should not be checked
                    Kind::Notification => packet.check(),
                });
            }
        }
    }
    pub fn dispatch(&mut self, packet: &CheckedPacket) -> Result<(), Error> {
        packet.encode(&mut self.writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_acknowledges_valid_packets() {
        let mut input: &[u8] = b"$packet#78";
        let mut tester = GdbServer::tester(&mut input);
        assert_eq!(
            tester.next_packet().unwrap(),
            Some(CheckedPacket::from_data(Kind::Packet, b"packet".to_vec()))
        );
        assert_eq!(tester.response(), b"+");
    }
    #[test]
    fn it_acknowledges_invalid_packets() {
        let mut input: &[u8] = b"$packet#99";
        let mut tester = GdbServer::tester(&mut input);
        assert_eq!(tester.next_packet().unwrap(), None);
        assert_eq!(tester.response(), b"-");
    }
    #[test]
    fn it_ignores_garbage() {
        let mut input: &[u8] = b"<garbage here yada yaya> $packet#13 $packet#37 more garbage $GARBA#GE-- $packet#78";
        let mut tester = GdbServer::tester(&mut input);
        assert_eq!(
            tester.next_packet().unwrap(),
            Some(CheckedPacket::from_data(Kind::Packet, b"packet".to_vec()))
        );
        assert_eq!(tester.response(), b"---+");
    }
}
