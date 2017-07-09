extern crate clap;
extern crate ring;
extern crate tuf;

use clap::{App, AppSettings, SubCommand, Arg, ArgMatches};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

fn main() {
    let matches = parser().get_matches();

    match run_main(matches) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}", e).unwrap();
            ::std::process::exit(1);
        }
    }
}

fn run_main(matches: ArgMatches) -> Result<(), String> {
    if let Some(matches) = matches.subcommand_matches("keygen") {
        let typ = matches.value_of("type").unwrap();
        keygen(typ)
    } else {
        unreachable!() // because of AppSettings::SubcommandRequiredElseHelp
    }
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("tuf")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CLI tool for managing TUF repositories")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(SubCommand::with_name("keygen")
            .about("Generate private keys and print them as PKCS#8v2 DER to STDOUT")
            .arg(Arg::with_name("type")
                .takes_value(true)
                .default_value("ed25519")
                .possible_values(&["ed25519", "rsa-2048", "rsa-4096"])
                .help("The type of key to generate. \
                      Note: rsa-XXX requires `openssl` to be on the PATH.")
            )
        )
}

fn keygen(typ: &str) -> Result<(), String> {
    let der = match typ {
        "ed25519" => {
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|e| format!("Failed to generate key: {:?}", e))?
                .to_vec()
        }
        "rsa-2048" => rsa_gen(2048)?,
        "rsa-4096" => rsa_gen(4096)?,
        _ => unreachable!(),
    };

    io::stdout().write(&der).map(|_| ()).map_err(|e| {
        format!("Failed to write to STDOUT: {:?}", e)
    })
}

fn rsa_gen(size: u32) -> Result<Vec<u8>, String> {
    let gen = Command::new("openssl")
        .args(
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                &format!("rsa_keygen_bits:{}", size),
                "-pkeyopt",
                "rsa_keygen_pubexp:65537",
                "-outform",
                "der",
            ],
        )
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{:?}", e))?;

    let mut pk8 = Command::new("openssl")
        .args(
            &[
                "pkcs8",
                "-inform",
                "der",
                "-topk8",
                "-nocrypt",
                "-outform",
                "der",
            ],
        )
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{:?}", e))?;

    match pk8.stdin {
        Some(ref mut stdin) => {
            for byte in gen.stdout.ok_or("Failed to get stdout handle")?.bytes() {
                stdin
                    .write(&[byte.map_err(|e| format!("Couldn't read byte: {:?}", e))?])
                    .map_err(|e| format!("Failed to write to stdin: {:?}", e))?;
            }
        }
        None => return Err("Failed to get stdin".into()),
    };

    let out = pk8.wait_with_output().map_err(|e| {
        format!("Failed to get stdout: {:?}", e)
    })?;

    Ok(out.stdout)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_clap() {
        let _ = parser();
    }
}
