use crate::{parser::CHECKSUM_LEN, Error};

use std::{
    cmp,
    io::prelude::*,
    ops::Deref,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Notification, // %
    Packet, // $
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncheckedPacket {
    pub kind: Kind,
    pub data: Vec<u8>,
    pub checksum: [u8; CHECKSUM_LEN as usize],
}
impl UncheckedPacket {
    /// Return the integer parsed from the hexadecimal expected
    /// checksum.
    ///
    /// ```rust
    /// # use gdb_protocol::packet::{Kind, UncheckedPacket};
    /// let packet = UncheckedPacket {
    ///     kind: Kind::Packet,
    ///     data: b"Hello, World!".to_vec(),
    ///     checksum: *b"BA",
    /// };
    /// assert_eq!(packet.expected_checksum().unwrap(), 186);
    /// ```
    pub fn expected_checksum(&self) -> Result<u8, Error> {
        let string = std::str::from_utf8(&self.checksum).map_err(|err| Error::NonUtf8(self.checksum.to_vec(), err))?;
        u8::from_str_radix(string, 16).map_err(|err| Error::NonNumber(string.to_owned(), err))
    }

    /// Return the actual checksum, derived from the data.
    ///
    /// ```rust
    /// # use gdb_protocol::packet::{Kind, UncheckedPacket};
    /// let packet = UncheckedPacket {
    ///     kind: Kind::Packet,
    ///     data: b"Hello, World!".to_vec(),
    ///     checksum: *b"BA",
    /// };
    /// assert_eq!(packet.actual_checksum(), 105);
    /// ```
    ///
    /// As per the GDB specification, this is currently a sum of all characters, modulo 256.
    /// The same result can be compared with
    ///
    /// ```rust
    /// # use gdb_protocol::packet::{Kind, UncheckedPacket};
    /// # fn test(input: &str) {
    /// #     assert_eq!(
    /// #         UncheckedPacket {
    /// #             kind: Kind::Packet,
    /// #             data: input.as_bytes().to_owned(),
    /// #             checksum: *b"00",
    /// #         }.actual_checksum(),
    /// (input.bytes().map(|x| usize::from(x)).sum::<usize>() % 256) as u8
    /// #     );
    /// # }
    /// # test("Hello, World!");
    /// # test("The history books say you live up to be 86 years old, Mr. Queen.");
    /// # test("All you care about is money. This town deserves a better class of criminals.");
    /// # test("Hello. I'm the Doctor. So basically, run.");
    /// # test("Batman! What are you doing? You're *completely* outnumbered here. Are you *nuts*?");
    /// ```
    ///
    /// however, this function is more efficient and won't go out of
    /// bounds.
    pub fn actual_checksum(&self) -> u8 {
        let mut hash: u8 = 0;
        for &b in &self.data {
            hash = hash.wrapping_add(b);
        }
        hash
    }

    /// Encode the packet into a long binary string, written to a
    /// writer of choice. You can receive a Vec<u8> by taking
    /// advantage of the fact that they implement io::Write:
    ///
    /// ```rust
    /// # use gdb_protocol::packet::{Kind, UncheckedPacket};
    /// let mut encoded = Vec::new();
    /// UncheckedPacket {
    ///     kind: Kind::Packet,
    ///     data: b"these must be escaped: # $ } *".to_vec(),
    ///     checksum: *b"00",
    /// }.encode(&mut encoded);
    /// assert_eq!(
    ///     encoded,
    ///     b"$these must be escaped: }\x03 }\x04 }] }\x0a#00".to_vec()
    /// );
    /// ```
    ///
    /// Currently multiple series repeated characters aren't
    /// shortened, however, this may change at any time and you should
    /// not rely on the output of this function being exactly one of
    /// multiple representations.
    pub fn encode<W>(&self, w: &mut W) -> Result<(), Error>
        where W: Write
    {
        w.write_all(&[match self.kind {
            Kind::Notification => b'%',
            Kind::Packet => b'$',
        }])?;

        let mut remaining: &[u8] = &self.data;
        while !remaining.is_empty() {
            let escape1 = memchr::memchr3(b'#', b'$', b'}', remaining);
            let escape2 = memchr::memchr(b'*', remaining);

            let escape = cmp::min(
                escape1.unwrap_or(remaining.len()),
                escape2.unwrap_or(remaining.len()),
            );

            w.write_all(&remaining[..escape])?;
            remaining = &remaining[escape..];

            if let Some(&b) = remaining.first() {
                dbg!(b as char);
                // memchr found a character that needs escaping, so let's do that
                w.write_all(&[b'}', b ^ 0x20])?;
                remaining = &remaining[1..];
            }
        }

        w.write_all(&[b'#'])?;
        w.write_all(&self.checksum)?;
        Ok(())
    }

    /// Will return a checked packet if, and only if, the checksums
    /// match. If you know the packet wasn't corrupted and want to
    /// bypass the check, use `CheckedPacket::assume_checked`.
    ///
    /// ```rust
    /// # use gdb_protocol::packet::{Kind, UncheckedPacket};
    /// assert!(UncheckedPacket {
    ///     kind: Kind::Packet,
    ///     data: b"Rust is an amazing programming language".to_vec(),
    ///     checksum: *b"00",
    /// }.check().is_none());
    /// assert!(UncheckedPacket {
    ///     kind: Kind::Packet,
    ///     data: b"Rust is an amazing programming language".to_vec(),
    ///     checksum: *b"C7",
    /// }.check().is_some());
    /// ```
    pub fn check(self) -> Option<CheckedPacket> {
        if self.expected_checksum().ok() == Some(self.actual_checksum()) {
            Some(CheckedPacket::assume_checked(self))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedPacket {
    unchecked: UncheckedPacket,
}
impl CheckedPacket {
    /// If you know the packet isn't corrupted, this function bypasses
    /// the checksum verification.
    pub fn assume_checked(unchecked: UncheckedPacket) -> Self {
        Self { unchecked }
    }
    /// If you intend to mutate the packet's internals, you must first
    /// convert it to an unchecked packet so it isn't marked as
    /// checked.
    pub fn invalidate_check(self) -> UncheckedPacket {
        self.unchecked
    }

    /// The empty packet is used when you get a packet which you just
    /// don't understand. Replying an empty packet means "I don't
    /// support this feature".
    ///
    /// ```rust
    /// # use gdb_protocol::packet::CheckedPacket;
    /// let mut encoded = Vec::new();
    /// CheckedPacket::empty().encode(&mut encoded);
    /// assert_eq!(encoded, b"$#00")
    /// ```
    pub fn empty() -> Self {
        Self::assume_checked(UncheckedPacket {
            kind: Kind::Packet,
            data: Vec::new(),
            checksum: *b"00",
        })
    }

    /// Creates a packet from the inputted binary data, and generates
    /// the checksum from it.
    /// ```rust
    /// # use gdb_protocol::packet::{CheckedPacket, Kind, UncheckedPacket};
    /// assert_eq!(
    ///     CheckedPacket::from_data(Kind::Packet, b"Hello, World!".to_vec()).invalidate_check(),
    ///     UncheckedPacket {
    ///         kind: Kind::Packet,
    ///         data: b"Hello, World!".to_vec(),
    ///         checksum: *b"69"
    ///     },
    /// )
    /// ```
    pub fn from_data(kind: Kind, data: Vec<u8>) -> Self {
        let mut packet = UncheckedPacket {
            kind,
            data,
            checksum: [0; CHECKSUM_LEN as usize],
        };
        let actual = packet.actual_checksum();
        write!(&mut packet.checksum[..], "{:02X}", actual).unwrap();
        Self::assume_checked(packet)
    }

}
// No DerefMut, because then the checksum/data could be modified
impl Deref for CheckedPacket {
    type Target = UncheckedPacket;

    fn deref(&self) -> &Self::Target {
        &self.unchecked
    }
}
