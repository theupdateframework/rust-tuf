use itoa;
use json;
use std::collections::BTreeMap;

pub fn canonicalize(jsn: &json::Value) -> Result<Vec<u8>, String> {
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
        match self {
            &Value::Null => Ok(buf.extend(b"null")),
            &Value::Bool(true) => Ok(buf.extend(b"true")),
            &Value::Bool(false) => Ok(buf.extend(b"false")),
            &Value::Number(Number::I64(n)) => {
                itoa::write(buf, n).map(|_| ()).map_err(|err| {
                    format!("Write error: {}", err)
                })
            }
            &Value::Number(Number::U64(n)) => {
                itoa::write(buf, n).map(|_| ()).map_err(|err| {
                    format!("Write error: {}", err)
                })
            }
            &Value::String(ref s) => {
                // this mess is abusing serde_json to get json escaping
                let s = json::Value::String(s.clone());
                let s = json::to_string(&s).map_err(|e| format!("{:?}", e))?;
                Ok(buf.extend(s.as_bytes()))
            }
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
            }
            &Value::Object(ref obj) => {
                buf.push(b'{');
                let mut first = true;
                for (k, v) in obj.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    first = false;

                    // this mess is abusing serde_json to get json escaping
                    let k = json::Value::String(k.clone());
                    let k = json::to_string(&k).map_err(|e| format!("{:?}", e))?;
                    buf.extend(k.as_bytes());

                    buf.push(b':');
                    v.write(&mut buf)?;
                }
                Ok(buf.push(b'}'))
            }
        }
    }
}

enum Number {
    I64(i64),
    U64(u64),
}

fn convert(jsn: &json::Value) -> Result<Value, String> {
    match jsn {
        &json::Value::Null => Ok(Value::Null),
        &json::Value::Bool(b) => Ok(Value::Bool(b)),
        &json::Value::Number(ref n) => {
            n.as_i64()
                .map(Number::I64)
                .or(n.as_u64().map(Number::U64))
                .map(Value::Number)
                .ok_or_else(|| String::from("only i64 and u64 are supported"))
        }
        &json::Value::Array(ref arr) => {
            let mut out = Vec::new();
            for res in arr.iter().map(|v| convert(v)) {
                out.push(res?)
            }
            Ok(Value::Array(out))
        }
        &json::Value::Object(ref obj) => {
            let mut out = BTreeMap::new();
            for (k, v) in obj.iter() {
                let _ = out.insert(k.clone(), convert(v)?);
            }
            Ok(Value::Object(out))
        }
        &json::Value::String(ref s) => Ok(Value::String(s.clone())),
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
