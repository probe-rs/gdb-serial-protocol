use super::{
    packet::{Kind, UncheckedPacket},
    Error,
};

use std::{cmp, iter, mem};

enum State {
    Type,         // % or $
    Data,         // packet-data#
    Escape,       // "}x" = 'x' | 0x20
    Repeat,       // "x*y" = "x" * ('y' - 29)
    Checksum(u8), // checksum
}

pub const CHECKSUM_LEN: u8 = 2;

pub struct Parser {
    state: State,
    kind: Kind,
    data: Vec<u8>,
    checksum: [u8; CHECKSUM_LEN as usize],
}
impl Default for Parser {
    fn default() -> Self {
        Self {
            state: State::Type,

            // placeholders:
            kind: Kind::Notification,
            data: Vec::new(),
            checksum: [0; CHECKSUM_LEN as usize],
        }
    }
}
impl Parser {
    /// Parse as much of `input` as possible into a packet. Returns
    /// the number of bytes read (the rest will need to be re-fed),
    /// and maybe a packet which will need handling.
    ///
    /// ```rust
    /// # use gdb_protocol::{Error, packet::{Kind, UncheckedPacket}, parser::Parser};
    /// # let mut parser = Parser::default();
    /// assert_eq!(
    ///     parser.feed(b"$hello#14").unwrap(),
    ///     (9, Some(UncheckedPacket {
    ///         kind: Kind::Packet,
    ///         data: b"hello".to_vec(),
    ///         checksum: *b"14",
    ///     }))
    /// );
    /// ```
    ///
    /// Apart from splitting the input up and expanding the data,
    /// nothing else is done. No checksums are compared, no data is
    /// handled. This is just the most basic building block used to
    /// supply data that can be further validated and interpreted.
    ///
    /// ```rust
    /// # use gdb_protocol::{Error, packet::{Kind, UncheckedPacket}, parser::Parser};
    /// # let mut parser = Parser::default();
    /// assert_eq!(
    ///     parser.feed(b"$in:valid}]}}Hello* }]*!CHECKS#UM").unwrap(),
    ///     (33, Some(UncheckedPacket {
    ///         kind: Kind::Packet,
    ///         data: b"in:valid}]Helloooo}}}}}CHECKS".to_vec(),
    ///         checksum: *b"UM",
    ///     }))
    /// );
    /// ```
    ///
    /// Note that although the GDB protocol mostly only uses 7 bits,
    /// this will *not* work without the 8th bit clear. This is to
    /// make the overhead of updating each element in the list
    /// optional. Although that's simple: *Every* element's 8th bit
    /// can be cleared so just do that before passing it to the
    /// parser.
    ///
    /// ```rust
    /// # use gdb_protocol::{Error, packet::{Kind, UncheckedPacket}, parser::Parser};
    /// # let mut parser = Parser::default();
    /// assert_eq!(
    ///     parser.feed(&[b'%', 1, 2, 99, 255, 128, 0, 200, b'#', 0, 0]).unwrap(),
    ///     (11, Some(UncheckedPacket {
    ///         kind: Kind::Notification,
    ///         data: vec![1, 2, 99, 255, 128, 0, 200],
    ///         checksum: [0, 0],
    ///     }))
    /// );
    /// ```
    ///
    /// This is a state machine: You may input half a packet now and
    /// half in a later invocation.
    ///
    /// ```rust
    /// # use gdb_protocol::{Error, parser::Parser};
    /// #
    /// # let full_input = b"$hello#14";
    /// # #[allow(non_snake_case)]
    /// # fn getRandomNumber() -> usize {
    /// #     return 4; // chosen by a fair dice roll.
    /// #               // guaranteed to be random.
    /// # }
    /// # let random_index = getRandomNumber();
    /// let mut parser1 = Parser::default();
    /// let (full_len, full_packet) = parser1.feed(full_input)?;
    ///
    /// let mut parser2 = Parser::default();
    /// let (start_input, end_input) = full_input.split_at(random_index);
    /// let (start_len, start_packet) = parser2.feed(start_input)?;
    /// let (end_len, end_packet) = parser2.feed(end_input)?;
    ///
    /// assert_eq!(start_len + end_len, full_len, "The total consumed lengths must be equal");
    /// assert_eq!(start_packet.or(end_packet), full_packet, "The end packets must be equal");
    /// # Ok::<(), Error>(())
    /// ```
    pub fn feed(&mut self, input: &[u8]) -> Result<(usize, Option<UncheckedPacket>), Error> {
        let mut read = 0;
        loop {
            let (partial, packet) = self.feed_one(&input[read..])?;
            read += partial;
            debug_assert!(read <= input.len());

            if read == input.len() || packet.is_some() {
                return Ok((read, packet));
            }
        }
    }
    fn feed_one(&mut self, input: &[u8]) -> Result<(usize, Option<UncheckedPacket>), Error> {
        let first = match input.first() {
            Some(b) => *b,
            None => return Ok((0, None)),
        };

        match self.state {
            State::Type => {
                let start = memchr::memchr2(b'%', b'$', input);

                match start.map(|pos| input[pos]) {
                    Some(b'%') => self.kind = Kind::Notification,
                    Some(b'$') => self.kind = Kind::Packet,
                    Some(_) => unreachable!("did memchr just lie to me?!"),
                    None => (),
                }

                if start.is_some() {
                    self.state = State::Data;
                }

                Ok((start.map(|n| n + 1).unwrap_or(input.len()), None))
            }
            State::Data => {
                let end = memchr::memchr3(b'#', b'}', b'*', input);

                match end.map(|pos| input[pos]) {
                    Some(b'#') => self.state = State::Checksum(0),
                    Some(b'}') => self.state = State::Escape,
                    Some(b'*') => self.state = State::Repeat,
                    Some(_) => unreachable!("did memchr just lie to me?!"),
                    None => (),
                }

                self.data
                    .extend_from_slice(&input[..end.unwrap_or(input.len())]);
                Ok((end.map(|n| n + 1).unwrap_or(input.len()), None))
            }
            State::Escape => {
                self.data.push(first ^ 0x20);
                self.state = State::Data;
                Ok((1, None))
            }
            State::Repeat => {
                let c = *self
                    .data
                    .last()
                    .expect("State::Repeat must only be used once data has been inserted");
                let count = first.saturating_sub(29);
                self.data.extend(iter::repeat(c).take(count.into()));
                self.state = State::Data;
                Ok((1, None))
            }
            State::Checksum(mut i) => {
                let read = cmp::min((CHECKSUM_LEN - i) as usize, input.len());

                self.checksum[i as usize..].copy_from_slice(&input[..read]);
                i += read as u8; // read <= CHECKSUM_LEN

                if i < CHECKSUM_LEN {
                    self.state = State::Checksum(i);
                    Ok((read, None))
                } else {
                    self.state = State::Type;

                    Ok((
                        read,
                        Some(UncheckedPacket {
                            kind: self.kind,
                            data: mem::replace(&mut self.data, Vec::new()),
                            checksum: self.checksum,
                        }),
                    ))
                }
            }
        }
    }
}
