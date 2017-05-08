//! Helper for writing ASN.1

use ring;
use std::io::{self, Write};
use untrusted::Input;

use der::Tag;

pub struct Asn1<'a, W: Write + 'a> {
    writer: &'a mut W,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error;

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Error {
        Error
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Error {
        Error
    }
}


impl<'a, W: Write> Asn1<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Asn1 { writer: writer }
    }

    fn length_of_length(len: usize) -> u8 {
        let mut i = len;
        let mut num_bytes = 1;

        while i > 255 {
            num_bytes += 1;
            i >>= 8;
        }

        num_bytes
    }

    fn write_len(&mut self, len: usize) -> Result<(), Error> {
        if len >= 128 {
            let n = Self::length_of_length(len);
            self.writer.write_all(&[0x80 | n])?;

            for i in (1..n + 1).rev() {
                self.writer.write_all(&[(len >> ((i - 1) * 8)) as u8])?;
            }
        } else {
            self.writer.write_all(&[len as u8])?;
        }

        Ok(())
    }

    pub fn write_integer(&mut self, input: Input) -> Result<(), Error> {
        self.writer.write_all(&[Tag::Integer as u8])?;
        let mut buf = Vec::new();

        input.read_all(Error, |read| {
                while let Ok(byte) = read.read_byte() {
                    buf.push(byte);
                }

                Ok(())
            })?;

        self.write_len(buf.len())?;

        Ok(self.writer.write_all(&mut buf)?)
    }

    pub fn write_sequence<F: FnOnce(&mut Asn1<Vec<u8>>) -> Result<(), Error>>
        (&mut self,
         func: F)
         -> Result<(), Error> {
        self.writer.write_all(&[Tag::Sequence as u8])?;
        let mut buf = Vec::new();

        {
            let mut inner = Asn1::new(&mut buf);
            func(&mut inner)?;
        }

        self.write_len(buf.len())?;
        Ok(self.writer.write_all(&buf)?)
    }
}
