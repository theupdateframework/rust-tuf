// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Building blocks for parsing DER-encoded ASN.1 structures.
//!
//! This module contains the foundational parts of an ASN.1 DER parser.

use ring;
use std::io::{self, Write};
use untrusted;

pub const CONSTRUCTED: u8 = 1 << 5;

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum Tag {
    Eoc = 0x00,
    Integer = 0x02,
    BitString = 0x03,
    Null = 0x05,
    Oid = 0x06,
    Sequence = CONSTRUCTED | 0x10, // 0x30
}

pub fn expect_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
) -> Result<untrusted::Input<'a>, ring::error::Unspecified> {

    let (actual_tag, inner) = read_tag_and_get_value(input)?;
    if (tag as usize) != (actual_tag as usize) {
        return Err(ring::error::Unspecified);
    }
    Ok(inner)
}

pub fn read_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<(u8, untrusted::Input<'a>), ring::error::Unspecified> {
    let tag = input.read_byte()?;

    if tag as usize == Tag::Eoc as usize {
        return Ok((tag, untrusted::Input::from(&[])));
    }

    if (tag & 0x1F) == 0x1F {
        return Err(ring::error::Unspecified); // High tag number form is not allowed.
    }

    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length.
    let length = match input.read_byte()? {
        n if (n & 0x80) == 0 => n as usize,
        0x81 => {
            let second_byte = input.read_byte()?;
            if second_byte < 128 {
                return Err(ring::error::Unspecified); // Not the canonical encoding.
            }
            second_byte as usize
        }
        0x82 => {
            let second_byte = input.read_byte()? as usize;
            let third_byte = input.read_byte()? as usize;
            let combined = (second_byte << 8) | third_byte;

            if combined < 256 {
                return Err(ring::error::Unspecified); // Not the canonical encoding.
            }
            combined
        }
        _ => {
            return Err(ring::error::Unspecified); // We don't support longer lengths.
        }
    };


    let inner = input.skip_and_get_input(length)?;
    Ok((tag, inner))
}

pub fn read_nested<'a, F, R, E: Copy>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
    error: E,
    decoder: F,
) -> Result<R, E>
where
    F: FnOnce(&mut untrusted::Reader<'a>) -> Result<R, E>,
{
    let inner = expect_tag_and_get_value(input, tag).map_err(|_| error)?;
    inner.read_all(error, decoder)
}

fn nonnegative_integer<'a>(
    input: &mut untrusted::Reader<'a>,
    min_value: u8,
) -> Result<untrusted::Input<'a>, ring::error::Unspecified> {
    // Verify that |input|, which has had any leading zero stripped off, is the
    // encoding of a value of at least |min_value|.
    fn check_minimum(
        input: untrusted::Input,
        min_value: u8,
    ) -> Result<(), ring::error::Unspecified> {
        input.read_all(ring::error::Unspecified, |input| {
            let first_byte = input.read_byte()?;
            if input.at_end() && first_byte < min_value {
                return Err(ring::error::Unspecified);
            }
            let _ = input.skip_to_end();
            Ok(())
        })
    }

    let value = expect_tag_and_get_value(input, Tag::Integer)?;

    value.read_all(ring::error::Unspecified, |input| {
        // Empty encodings are not allowed.
        let first_byte = input.read_byte()?;

        if first_byte == 0 {
            if input.at_end() {
                // |value| is the legal encoding of zero.
                if min_value > 0 {
                    return Err(ring::error::Unspecified);
                }
                return Ok(value);
            }

            let r = input.skip_to_end();
            r.read_all(ring::error::Unspecified, |input| {
                let second_byte = input.read_byte()?;
                if (second_byte & 0x80) == 0 {
                    // A leading zero is only allowed when the value's high bit
                    // is set.
                    return Err(ring::error::Unspecified);
                }
                let _ = input.skip_to_end();
                Ok(())
            })?;
            check_minimum(r, min_value)?;
            return Ok(r);
        }

        // Negative values are not allowed.
        if (first_byte & 0x80) != 0 {
            return Err(ring::error::Unspecified);
        }

        let _ = input.skip_to_end();
        check_minimum(value, min_value)?;
        Ok(value)
    })
}

/// Parses a positive DER integer, returning the big-endian-encoded value, sans
/// any leading zero byte.
#[inline]
pub fn positive_integer<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>, ring::error::Unspecified> {
    nonnegative_integer(input, 1)
}


pub struct Der<'a, W: Write + 'a> {
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


impl<'a, W: Write> Der<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Der { writer: writer }
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

    pub fn write_null(&mut self) -> Result<(), Error> {
        Ok(self.writer.write_all(&[Tag::Null as u8, 0])?)
    }

    pub fn write_element(&mut self, tag: Tag, input: untrusted::Input) -> Result<(), Error> {
        self.writer.write_all(&[tag as u8])?;
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

    pub fn write_sequence<F: FnOnce(&mut Der<Vec<u8>>) -> Result<(), Error>>(
        &mut self,
        func: F,
    ) -> Result<(), Error> {
        self.writer.write_all(&[Tag::Sequence as u8])?;
        let mut buf = Vec::new();

        {
            let mut inner = Der::new(&mut buf);
            func(&mut inner)?;
        }

        self.write_len(buf.len())?;
        Ok(self.writer.write_all(&buf)?)
    }

    pub fn write_raw(&mut self, input: untrusted::Input) -> Result<(), Error> {
        Ok(self.writer.write_all(input.as_slice_less_safe())?)
    }

    pub fn write_bit_string<F: FnOnce(&mut Der<Vec<u8>>) -> Result<(), Error>>(
        &mut self,
        func: F,
    ) -> Result<(), Error> {
        self.writer.write_all(&[Tag::BitString as u8])?;
        let mut buf = Vec::new();
        // push 0x00 byte to say "no unused bits"
        buf.push(0x00);

        {
            let mut inner = Der::new(&mut buf);
            func(&mut inner)?;
        }

        self.write_len(buf.len())?;
        Ok(self.writer.write_all(&buf)?)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use untrusted;

    fn with_good_i<F, R>(value: &[u8], f: F)
    where
        F: FnOnce(&mut untrusted::Reader) -> Result<R, ring::error::Unspecified>,
    {
        let r = untrusted::Input::from(value).read_all(ring::error::Unspecified, f);
        assert!(r.is_ok());
    }

    fn with_bad_i<F, R>(value: &[u8], f: F)
    where
        F: FnOnce(&mut untrusted::Reader) -> Result<R, ring::error::Unspecified>,
    {
        let r = untrusted::Input::from(value).read_all(ring::error::Unspecified, f);
        assert!(r.is_err());
    }

    static ZERO_INTEGER: &'static [u8] = &[0x02, 0x01, 0x00];

    static GOOD_POSITIVE_INTEGERS: &'static [(&'static [u8], u8)] =
        &[
            (&[0x02, 0x01, 0x01], 0x01),
            (&[0x02, 0x01, 0x02], 0x02),
            (&[0x02, 0x01, 0x7e], 0x7e),
            (&[0x02, 0x01, 0x7f], 0x7f),

            // Values that need to have an 0x00 prefix to disambiguate them from
            // them from negative values.
            (&[0x02, 0x02, 0x00, 0x80], 0x80),
            (&[0x02, 0x02, 0x00, 0x81], 0x81),
            (&[0x02, 0x02, 0x00, 0xfe], 0xfe),
            (&[0x02, 0x02, 0x00, 0xff], 0xff),
        ];

    static BAD_NONNEGATIVE_INTEGERS: &'static [&'static [u8]] = &[
        &[], // At end of input
        &[0x02], // Tag only
        &[0x02, 0x00], // Empty value

        // Length mismatch
        &[0x02, 0x00, 0x01],
        &[0x02, 0x01],
        &[0x02, 0x01, 0x00, 0x01],
        &[0x02, 0x01, 0x01, 0x00], // Would be valid if last byte is ignored.
        &[0x02, 0x02, 0x01],

        // Negative values
        &[0x02, 0x01, 0x80],
        &[0x02, 0x01, 0xfe],
        &[0x02, 0x01, 0xff],

        // Values that have an unnecessary leading 0x00
        &[0x02, 0x02, 0x00, 0x00],
        &[0x02, 0x02, 0x00, 0x01],
        &[0x02, 0x02, 0x00, 0x02],
        &[0x02, 0x02, 0x00, 0x7e],
        &[0x02, 0x02, 0x00, 0x7f],
    ];

    #[test]
    fn test_positive_integer() {
        with_bad_i(ZERO_INTEGER, |input| {
            let _ = positive_integer(input)?;
            Ok(())
        });
        for &(ref test_in, test_out) in GOOD_POSITIVE_INTEGERS.iter() {
            with_good_i(test_in, |input| {
                let test_out = [test_out];
                assert_eq!(
                    positive_integer(input)?,
                    untrusted::Input::from(&test_out[..])
                );
                Ok(())
            });
        }
        for &test_in in BAD_NONNEGATIVE_INTEGERS.iter() {
            with_bad_i(test_in, |input| {
                let _ = positive_integer(input)?;
                Ok(())
            });
        }
    }
}
