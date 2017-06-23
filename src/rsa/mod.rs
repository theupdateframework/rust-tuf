//! Helper module for RSA key encoding / decoding.

pub mod der;

use untrusted::Input;

use self::der::{Tag, Der};

/// Corresponds to `1.2.840.113549.1.1.1 rsaEncryption(PKCS #1)`
const RSA_PKCS1_OID: &'static [u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

pub fn from_pkcs1(input: &[u8]) -> Option<Vec<u8>> {
    let _input = Input::from(&input);
    _input
        .read_all(der::Error, |i| {
            der::nested(i, Tag::Sequence, der::Error, |i| {
                let _ = der::positive_integer(i)?;
                let _ = der::positive_integer(i)?;
                // if the input was already pkcs1, just return it
                Ok(input.to_vec())
            })
        })
        .ok()
}

pub fn from_spki(input: &[u8]) -> Option<Vec<u8>> {
    let _input = Input::from(&input);
    _input
        .read_all(der::Error, |i| {
            der::nested(i, Tag::Sequence, der::Error, |i| {
                der::nested(i, Tag::Sequence, der::Error, |i| {
                    let oid = der::expect_tag_and_get_value(i, Tag::Oid)?;
                    if oid != Input::from(RSA_PKCS1_OID) {
                        return Err(der::Error);
                    }

                    let _ = der::expect_tag_and_get_value(i, Tag::Null)?;
                    Ok(())
                })?;

                der::nested(i, Tag::BitString, der::Error, |i| {
                    let _ = der::expect_tag_and_get_value(i, Tag::Eoc)?;
                    Ok(i.skip_to_end().iter().cloned().collect())
                })
            })
        })
        .ok()
}

#[cfg(test)]
fn write_pkcs1(n: Input, e: Input) -> Result<Vec<u8>, der::Error> {
    let mut output = Vec::new();
    {
        let mut _der = Der::new(&mut output);
        _der.write_sequence(|_der| {
                                _der.write_element(Tag::Integer, n)?;
                                _der.write_element(Tag::Integer, e)
                            })?;
    }

    Ok(output)
}

pub fn write_spki(pkcs1: &[u8]) -> Result<Vec<u8>, der::Error> {
    let mut output = Vec::new();
    {
        let mut _der = Der::new(&mut output);
        _der.write_sequence(|_der| {
                                _der.write_sequence(|_der| {
                        _der.write_element(Tag::Oid, Input::from(RSA_PKCS1_OID))?;
                        _der.write_null()
                    })?;
                                _der.write_element(Tag::BitString, Input::from(pkcs1))
                            })?;
    }

    Ok(output)
}

#[cfg(test)]
fn write_spki_from_params(n: Input, e: Input) -> Result<Vec<u8>, der::Error> {
    let bit_string = write_pkcs1(n, e)?;
    write_spki(&bit_string)
}

#[cfg(test)]
mod test {
    use super::*;
    use pem;
    use std::fs::File;
    use std::io::Read;

    fn read_file(path: &str) -> Vec<u8> {
        let mut file = File::open(path).expect("couldn't open file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("couldn't read file");
        buf
    }

    #[test]
    fn test_write_pkcs1() {
        let contents = read_file("./tests/rsa/pkcs1-1.pub");
        let contents = pem::parse(&contents).expect("not PEM").contents;

        let n = &[0x00, 0x9d, 0xda, 0x85, 0x17, 0x15, 0x67, 0xab, 0xb1, 0x63, 0x8a, 0x13, 0x01,
                  0xee, 0xc0, 0x63, 0x7c, 0xc3, 0x08, 0x4b, 0x6d, 0x75, 0xd8, 0x70, 0x74, 0x3d,
                  0xab, 0x98, 0xef, 0x00, 0xd0, 0xf2, 0x04, 0xe7, 0x7d, 0xb5, 0xa4, 0x08, 0xe3,
                  0x90, 0xda, 0x4b, 0xe1, 0xd1, 0xff, 0x0f, 0x87, 0x8d, 0x6b, 0x43, 0x58, 0x99,
                  0x88, 0xf6, 0x99, 0xab, 0xe7, 0x90, 0xfb, 0x2a, 0xa1, 0x3c, 0x2b, 0x0f, 0x24,
                  0xa4, 0x9e, 0xab, 0xd1, 0xfc, 0xa0, 0xe0, 0xa8, 0x9f, 0x82, 0x48, 0xe5, 0xa7,
                  0xd2, 0x4d, 0x44, 0xe4, 0x0b, 0x43, 0x66, 0x03, 0x54, 0x8d, 0xdd, 0xc3, 0x0c,
                  0x26, 0xf5, 0x20, 0x36, 0xbf, 0xae, 0x05, 0x63, 0x9c, 0xf8, 0x81, 0xeb, 0xf7,
                  0x4a, 0x3a, 0xc4, 0x14, 0xee, 0xce, 0x99, 0x66, 0x9f, 0x3c, 0xe3, 0x18, 0x21,
                  0x8d, 0x68, 0xe3, 0x0b, 0xb7, 0xb3, 0xf7, 0xca, 0xe1, 0x7c, 0xab, 0xd5, 0x17,
                  0x6f, 0x50, 0xc1, 0x38, 0x1b, 0xea, 0x62, 0xeb, 0x46, 0x07, 0x95, 0x01, 0xfb,
                  0xd3, 0x1a, 0xd0, 0xae, 0x1c, 0xe6, 0x53, 0x27, 0x53, 0x2d, 0x08, 0x55, 0xbe,
                  0xa3, 0xd6, 0xd1, 0x02, 0x14, 0xa4, 0xa2, 0xe1, 0x14, 0xde, 0xa4, 0x0e, 0x54,
                  0x00, 0xe5, 0x79, 0x2c, 0x4d, 0x93, 0xe8, 0x6b, 0x3c, 0xf6, 0x44, 0x63, 0x85,
                  0x3c, 0x6f, 0x56, 0xc2, 0x80, 0x02, 0x3f, 0x76, 0xcf, 0x75, 0x46, 0x5f, 0x9a,
                  0x49, 0x47, 0xdc, 0xe6, 0xe9, 0x9a, 0xc0, 0x6e, 0x34, 0x9e, 0x9f, 0xd2, 0xdf,
                  0xbc, 0x55, 0xa0, 0x77, 0x61, 0xf3, 0xd5, 0x0c, 0xb8, 0x77, 0xd2, 0x66, 0xd2,
                  0x24, 0x9a, 0x25, 0xbe, 0x55, 0x1b, 0x4e, 0xbf, 0x3b, 0x82, 0x4c, 0x4f, 0x51,
                  0x57, 0x7c, 0x8b, 0xf6, 0x38, 0xfe, 0x4d, 0x97, 0x32, 0xa8, 0xc8, 0x3c, 0x69,
                  0xe5, 0x91, 0x15, 0x2c, 0x75, 0x8d, 0x92, 0xc1, 0xc7, 0x6b];

        let e = &[0x01, 0x00, 0x01];
        let bytes = write_pkcs1(Input::from(n), Input::from(e));

        assert_eq!(bytes, Ok(contents));
    }

    #[test]
    fn pkcs1_noop_conversion_1() {
        let contents = read_file("./tests/rsa/pkcs1-1.pub");
        let contents = pem::parse(&contents).expect("not PEM").contents;
        assert_eq!(from_pkcs1(&contents), Some(contents));
    }

    #[test]
    fn pkcs1_noop_conversion_2() {
        let contents = read_file("./tests/rsa/pkcs1-2.pub");
        let contents = pem::parse(&contents).expect("not PEM").contents;
        assert_eq!(from_pkcs1(&contents), Some(contents));
    }

    #[test]
    fn pkcs1_from_spki_conversion_1() {
        let spki = read_file("./tests/rsa/spki-1.pub");
        let spki = pem::parse(&spki).expect("not PEM").contents;

        let pkcs1 = read_file("./tests/rsa/pkcs1-1.pub");
        let pkcs1 = pem::parse(&pkcs1).expect("not PEM").contents;

        assert!(from_spki(&spki) == from_pkcs1(&pkcs1));
    }

    #[test]
    fn pkcs1_from_spki_conversion_2() {
        let spki = read_file("./tests/rsa/spki-2.pub");
        let spki = pem::parse(&spki).expect("not PEM").contents;

        let pkcs1 = read_file("./tests/rsa/pkcs1-2.pub");
        let pkcs1 = pem::parse(&pkcs1).expect("not PEM").contents;

        assert!(from_spki(&spki) == from_pkcs1(&pkcs1));
    }
}
