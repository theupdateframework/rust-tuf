//! Helper module for RSA key encoding / decoding.

use untrusted::Input;

use asn1::{self, Asn1};
use der::{self, Tag};

pub fn convert_to_pkcs1<'a>(input: &[u8]) -> Vec<u8> {
    from_pkcs1(input)
        .or_else(|| from_spki(input))
        .unwrap_or_else(|| input.to_vec())
}

fn from_pkcs1(input: &[u8]) -> Option<Vec<u8>> {
    let _input = Input::from(input.clone());
    _input.read_all(asn1::Error, |i| {
            der::nested(i, Tag::Sequence, asn1::Error, |i| {
                let _ = der::positive_integer(i)?;
                let _ = der::positive_integer(i)?;
                // if the input was already pkcs1, just return it
                Ok(input.to_vec())
            })
        })
        .ok()
}

fn from_spki(input: &[u8]) -> Option<Vec<u8>> {
    let _input = Input::from(input.clone());
    _input.read_all(asn1::Error, |i| {
            der::nested(i, Tag::Sequence, asn1::Error, |i| {
                der::nested(i, Tag::Sequence, asn1::Error, |i| {
                    let _ = der::expect_tag_and_get_value(i, Tag::OID)?;
                    // TODO check OID

                    let _ = der::expect_tag_and_get_value(i, Tag::Null)?;
                    Ok(())
                })?;

                der::nested(i, Tag::BitString, asn1::Error, |i| {
                    println!(">>>> A");
                    der::nested(i, Tag::Sequence, asn1::Error, |i| {
                        println!("{:?}", i);
                        println!(">>>> B");
                        let n = der::positive_integer(i)?;
                        println!(">>>> C");
                        let e = der::positive_integer(i)?;
                        println!(">>>> D");
                        write_pkcs1(n, e)
                    })
                })
            })
        })
        .ok()
}

fn write_pkcs1(n: Input, e: Input) -> Result<Vec<u8>, asn1::Error> {
    let mut output = Vec::new();
    {
        let mut asn1 = Asn1::new(&mut output);
        asn1.write_sequence(|_asn1| {
                _asn1.write_integer(n)?;
                _asn1.write_integer(e)
            })?;
    }

    Ok(output)
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
    fn pkcs1_noop_conversion() {
        let contents = read_file("./tests/rsa/pkcs1.pub");
        let contents = pem::parse(&contents).expect("not PEM").contents;
        assert_eq!(convert_to_pkcs1(&contents), contents);
    }

    #[test]
    fn pkcs1_from_spki_conversion() {
        let spki = read_file("./tests/rsa/spki.pub");
        let spki = pem::parse(&spki).expect("not PEM").contents;

        let pkcs1 = read_file("./tests/rsa/pkcs1.pub");
        let pkcs1 = pem::parse(&pkcs1).expect("not PEM").contents;

        for (i, (a, b)) in spki.iter().zip(pkcs1.iter()).enumerate() {
            println!("{} {} {}", i, a, b);
            if a != b {
                break
            }
        }

        assert_eq!(convert_to_pkcs1(&spki), pkcs1);
    }
}
