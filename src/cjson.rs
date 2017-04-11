//! Hack-y crate used for development until canonical_json supports serde 0.9
// TODO remove me

use itoa;
use json;
use std::collections::BTreeMap;
use std::io;

pub fn canonicalize(jsn: json::Value) -> Result<Vec<u8>, String> {
    let converted = convert(jsn)?;
    let mut buf = Vec::new();
    converted.write(&mut buf);
    Ok(buf)
}

enum Value {
    Array(Vec<Value>),
    Bool(bool),
    Null,
    Number(Number),
    Object(BTreeMap<String, Value>),
    String(String),
}

impl Value {
    fn write(&self, mut buf: &mut Vec<u8>) -> Result<(), String> {
        match self {
            &Value::Null => Ok(buf.extend(b"null")),
            &Value::Bool(true) => Ok(buf.extend(b"true")),
            &Value::Bool(false) => Ok(buf.extend(b"false")),
            &Value::Number(Number::I64(n)) => {
                itoa::write(buf, n)
                    .map(|_| ())
                    .map_err(|err| format!("Write error: {}", err))
            },
            &Value::Number(Number::U64(n)) => {
                itoa::write(buf, n)
                    .map(|_| ())
                    .map_err(|err| format!("Write error: {}", err))
            },
            &Value::String(ref s) => {
                escape_str(&mut buf, &s).map_err(|err| format!("Write error: {}", err))
            },
            &Value::Array(ref arr) => {
                buf.push(b'[');
                let mut first = true;
                for a in arr.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    a.write(&mut buf)?;
                    first = false;
                }
                Ok(buf.push(b']'))
            },
            &Value::Object(ref obj) => {
                buf.push(b'{');
                let mut first = true;
                for (k, v) in obj.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    first = false;
                    escape_str(&mut buf, &k).map_err(|err| format!("Write error: {}", err))?;
                    buf.push(b':');
                    v.write(&mut buf)?;
                }
                Ok(buf.push(b'}'))
            },
        }
    }
}

enum Number {
    I64(i64),
    U64(u64),
}

fn convert(jsn: json::Value) -> Result<Value, String> {
    match jsn {
        json::Value::Null => Ok(Value::Null),
        json::Value::Bool(b) => Ok(Value::Bool(b)),
        json::Value::Number(n) => {
            n.as_i64().map(Number::I64)
                .or(n.as_u64().map(Number::U64))
                .map(Value::Number)
                .ok_or(String::from("only i64 and u64 are supported"))
        },
        json::Value::Array(arr) => {
            let mut out = Vec::new();
            for res in arr.iter().cloned().map(|v| convert(v)) {
                out.push(res?)
            }
            Ok(Value::Array(out))
        },
        json::Value::Object(obj) => {
            let mut out = BTreeMap::new();
            for (k, v) in obj.iter() {
                let _ = out.insert(k.clone(), convert(v.clone())?);
            }
            Ok(Value::Object(out))
        },
        json::Value::String(s) => Ok(Value::String(s)),
        x => Err(format!("Value not supported: {}", x)),
    }
}

/// Serializes and escapes a `&str` into a JSON string.
fn escape_str<W>(wr: &mut W, value: &str) -> Result<(), io::Error>
    where W: io::Write,
{
    let bytes = value.as_bytes();

    wr.write_all(b"\"")?;

    let mut start = 0;

    for (i, &byte) in bytes.iter().enumerate() {
        let escape = ESCAPE[byte as usize];
        if escape == 0 {
            continue;
        }

        if start < i {
            wr.write_all(&bytes[start..i])?;
        }

        wr.write_all(&[b'\\', escape])?;

        start = i + 1;
    }

    if start != bytes.len() {
        wr.write_all(&bytes[start..])?;
    }

    wr.write_all(b"\"")?;
    Ok(())
}

const QU: u8 = b'"';  // \x22
const BS: u8 = b'\\'; // \x5C

// Lookup table of escape sequences. A value of b'x' at index i means that byte
// i is escaped as "\x" in JSON. A value of 0 means that byte i is not escaped.
#[cfg_attr(rustfmt, rustfmt_skip)]
static ESCAPE: [u8; 256] = [
    //  1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 0
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 1
    0,  0, QU,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 2
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 3
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 4
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, BS,  0,  0,  0, // 5
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 6
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 7
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 8
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 9
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // A
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // B
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // C
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // D
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // E
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // F
];

#[inline]
fn escape_char<W>(wr: &mut W, value: char) -> Result<(), io::Error>
    where W: io::Write,
{
    // FIXME: this allocation is required in order to be compatible with stable
    // rust, which doesn't support encoding a `char` into a stack buffer.
    let mut s = String::new();
    s.push(value);
    escape_str(wr, &s)
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::File;
    use std::io::Read;

    #[test]
    fn write_str() {
        let jsn = Value::String(String::from("wat"));
        let mut out = Vec::new();
        jsn.write(&mut out).expect("write failed");
        assert_eq!(&out, b"\"wat\"");
    }

    #[test]
    fn write_arr() {
        let jsn = Value::Array(vec![Value::String(String::from("wat")),
                                    Value::String(String::from("lol")),
                                    Value::String(String::from("no"))]);
        let mut out = Vec::new();
        jsn.write(&mut out).expect("write failed");
        assert_eq!(&out, b"[\"wat\",\"lol\",\"no\"]");
    }

    #[test]
    fn write_obj() {
        let mut map = BTreeMap::new();
        let arr = Value::Array(vec![Value::String(String::from("haha")),
                                    Value::String(String::from("omg so tired"))]);
        let _ = map.insert(String::from("lol"), arr);
        let jsn = Value::Object(map);
        let mut out = Vec::new();
        jsn.write(&mut out).expect("write failed");
        assert_eq!(&out, b"{\"lol\":[\"haha\",\"omg so tired\"]}");
    }

    #[test]
    fn root_json() {
        let expected = r#"{"signatures":[{"keyid":"d598ba283e45ed1e8c1dc874e6d208b03b6eed152d2a5b94d8958efe9affdcee","method":"ed25519","sig":"4df20f0695e638f5aceffebf4e27ed2abb8e9d38248353079c7e4d14a680cbe06f5c2c06c80f9bd17329333d227d754ea918c21386822ec62ae6d2aa86e6da0d"}],"signed":{"_type":"Root","consistent_snapshot":false,"expires":"2038-01-19T03:14:06Z","keys":{"1c94f6235eb6045029169c01be235a3378b6b1ea044bd714f534a7c14e97e1d8":{"keytype":"ed25519","keyval":{"public":"d28ff85e56a01a7fc545cccba7733f6bb97d736ebb80993f8198b3290edd4ba7"}},"a853bf784c696eccdd40cb5d93e4dae29d8acb3460e44c39882a56505149dd06":{"keytype":"ed25519","keyval":{"public":"200de6ac8ddcab44b9ed40ac71904d1c4c873cc1b20e183b6edaea6504657297"}},"d598ba283e45ed1e8c1dc874e6d208b03b6eed152d2a5b94d8958efe9affdcee":{"keytype":"ed25519","keyval":{"public":"2ca92b0dc29b78f64d28bcc2b1081025ea843a2ee88c3fe840fb9db85604ca98"}},"de9524fc89fc886b6de5d9a1149003c995187e142a9a0f531efc5d0d9577bf5e":{"keytype":"ed25519","keyval":{"public":"04aee67fc4119ac01b8645400ff5ca7af4953eae27accf0cecfe9e22ff098d4d"}}},"roles":{"root":{"keyids":["d598ba283e45ed1e8c1dc874e6d208b03b6eed152d2a5b94d8958efe9affdcee"],"threshold":1},"snapshot":{"keyids":["1c94f6235eb6045029169c01be235a3378b6b1ea044bd714f534a7c14e97e1d8"],"threshold":1},"targets":{"keyids":["de9524fc89fc886b6de5d9a1149003c995187e142a9a0f531efc5d0d9577bf5e"],"threshold":1},"timestamp":{"keyids":["a853bf784c696eccdd40cb5d93e4dae29d8acb3460e44c39882a56505149dd06"],"threshold":1}}}}"#.as_bytes();

        let mut file = File::open("./tests/repo-1/meta/root.json").expect("couldn't open root.json");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("couldn't read root.json");
        let jsn = json::from_slice(&buf).expect("not json");
        let out = canonicalize(jsn).expect("couldn't canonicalize");
        assert_eq!(out, expected.to_vec());
    }
}
