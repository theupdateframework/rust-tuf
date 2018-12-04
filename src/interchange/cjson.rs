use itoa;
use serde_json;
use std::collections::BTreeMap;

pub fn canonicalize(jsn: &serde_json::Value) -> Result<Vec<u8>, String> {
    let converted = convert(jsn)?;
    let mut buf = Vec::new();
    let _ = converted.write(&mut buf); // Vec<u8> impl always succeeds (or panics).
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
        match *self {
            Value::Null => {
                buf.extend(b"null");
                Ok(())
            }
            Value::Bool(true) => {
                buf.extend(b"true");
                Ok(())
            }
            Value::Bool(false) => {
                buf.extend(b"false");
                Ok(())
            }
            Value::Number(Number::I64(n)) => itoa::write(buf, n)
                .map(|_| ())
                .map_err(|err| format!("Write error: {}", err)),
            Value::Number(Number::U64(n)) => itoa::write(buf, n)
                .map(|_| ())
                .map_err(|err| format!("Write error: {}", err)),
            Value::String(ref s) => {
                // this mess is abusing serde_json to get json escaping
                let s = serde_json::Value::String(s.clone());
                let s = serde_json::to_string(&s).map_err(|e| format!("{:?}", e))?;
                buf.extend(s.as_bytes());
                Ok(())
            }
            Value::Array(ref arr) => {
                buf.push(b'[');
                let mut first = true;
                for a in arr.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    a.write(&mut buf)?;
                    first = false;
                }
                buf.push(b']');
                Ok(())
            }
            Value::Object(ref obj) => {
                buf.push(b'{');
                let mut first = true;
                for (k, v) in obj.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    first = false;

                    // this mess is abusing serde_json to get json escaping
                    let k = serde_json::Value::String(k.clone());
                    let k = serde_json::to_string(&k).map_err(|e| format!("{:?}", e))?;
                    buf.extend(k.as_bytes());

                    buf.push(b':');
                    v.write(&mut buf)?;
                }
                buf.push(b'}');
                Ok(())
            }
        }
    }
}

enum Number {
    I64(i64),
    U64(u64),
}

fn convert(jsn: &serde_json::Value) -> Result<Value, String> {
    match *jsn {
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Bool(b) => Ok(Value::Bool(b)),
        serde_json::Value::Number(ref n) => n
            .as_i64()
            .map(Number::I64)
            .or_else(|| n.as_u64().map(Number::U64))
            .map(Value::Number)
            .ok_or_else(|| String::from("only i64 and u64 are supported")),
        serde_json::Value::Array(ref arr) => {
            let mut out = Vec::new();
            for res in arr.iter().map(|v| convert(v)) {
                out.push(res?)
            }
            Ok(Value::Array(out))
        }
        serde_json::Value::Object(ref obj) => {
            let mut out = BTreeMap::new();
            for (k, v) in obj.iter() {
                let _ = out.insert(k.clone(), convert(v)?);
            }
            Ok(Value::Object(out))
        }
        serde_json::Value::String(ref s) => Ok(Value::String(s.clone())),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn write_str() {
        let jsn = Value::String(String::from("wat"));
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, b"\"wat\"");
    }

    #[test]
    fn write_arr() {
        let jsn = Value::Array(vec![
            Value::String(String::from("wat")),
            Value::String(String::from("lol")),
            Value::String(String::from("no")),
        ]);
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, b"[\"wat\",\"lol\",\"no\"]");
    }

    #[test]
    fn write_obj() {
        let mut map = BTreeMap::new();
        let arr = Value::Array(vec![
            Value::String(String::from("haha")),
            Value::String(String::from("new\nline")),
        ]);
        let _ = map.insert(String::from("lol"), arr);
        let jsn = Value::Object(map);
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, &b"{\"lol\":[\"haha\",\"new\\nline\"]}");
    }
}
