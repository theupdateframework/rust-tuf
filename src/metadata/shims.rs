use data_encoding::HEXLOWER;
use pem::{self, Pem};

use Result;
use error::Error;
use metadata::{self, KeyFormat, KeyType};
use rsa;

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(rename = "keytype")]
    typ: metadata::KeyType,
    #[serde(rename = "keyval")]
    public_key: PublicKeyValue,
}

impl PublicKey {
    pub fn from(public_key: &metadata::PublicKey) -> Result<Self> {
        let key_str = match public_key.format() {
            &KeyFormat::HexLower => HEXLOWER.encode(&*public_key.value().value()),
            &KeyFormat::Pkcs1 => {
                pem::encode(&Pem {
                    tag: "RSA PUBLIC KEY".to_string(),
                    contents: public_key.value().value().to_vec(),
                }).replace("\r", "")
            }
            &KeyFormat::Spki => {
                pem::encode(&Pem {
                    tag: "PUBLIC KEY".to_string(),
                    contents: rsa::write_spki(&public_key.value().value().to_vec())?,
                }).replace("\r", "")
            }
        };

        Ok(PublicKey {
            typ: public_key.typ().clone(),
            public_key: PublicKeyValue { public: key_str },
        })
    }

    pub fn try_into(self) -> Result<metadata::PublicKey> {
        let (key_bytes, format) = match self.typ {
            KeyType::Ed25519 => {
                let bytes = HEXLOWER.decode(self.public_key.public.as_bytes())?;
                (bytes, KeyFormat::HexLower)
            }
            KeyType::Rsa => {
                let _pem = pem::parse(self.public_key.public.as_bytes())?;
                match _pem.tag.as_str() {
                    "RSA PUBLIC KEY" => {
                        let bytes = rsa::from_pkcs1(&_pem.contents).ok_or(
                            Error::UnsupportedKeyFormat(
                                "PEM claimed to PKCS1 but could not be parsed"
                                    .into(),
                            ),
                        )?;
                        (bytes, KeyFormat::Pkcs1)
                    }
                    "PUBLIC KEY" => {
                        let bytes = rsa::from_spki(&_pem.contents).ok_or(
                            Error::UnsupportedKeyFormat(
                                "PEM claimed to SPKI but could not be parsed"
                                    .into(),
                            ),
                        )?;
                        (bytes, KeyFormat::Spki)
                    }
                    x => {
                        return Err(Error::UnsupportedKeyFormat(
                            format!("PEM with bad tag: {}", x),
                        ))
                    }
                }
            }
        };

        let key = metadata::PublicKeyValue::new(key_bytes);

        Ok(metadata::PublicKey::new(self.typ, format, key))
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKeyValue {
    public: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use json;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn parse_spki_json() {
        let mut jsn = json!({"keytype": "rsa", "keyval": {}});

        let mut file = File::open(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("rsa")
                .join("spki-1.pub"),
        ).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("keyval")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.clone()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }

    #[test]
    fn parse_pkcs1_json() {
        let mut jsn = json!({"keytype": "rsa", "keyval": {}});

        let mut file = File::open(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("rsa")
                .join("pkcs1-1.pub"),
        ).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("keyval")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.clone()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }

    #[test]
    fn parse_hex_json() {
        let mut jsn = json!({"keytype": "ed25519", "keyval": {}});
        let buf = "2bedead4feed".to_string();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("keyval")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.clone()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ, KeyType::Ed25519);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }
}
