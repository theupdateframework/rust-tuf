extern crate clap;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate tuf;

use clap::{App, ArgMatches, Arg, AppSettings, SubCommand};
use hyper::client::Client as HttpClient;
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write, Read};
use std::path::PathBuf;

use tuf::Result;
use tuf::error::Error;
use tuf::client::{Config, Client, DefaultTranslator};
use tuf::interchange::Json;
use tuf::metadata::TargetPath;
use tuf::repository::{FileSystemRepository, HttpRepository};

lazy_static! {
    static ref HOME_DIR: Option<PathBuf> = env::home_dir().map(|p| p.join(".tuf"));
}

#[derive(Deserialize)]
struct CliConfig {
    config_version: u32,
    remote: String,
}

fn main() {
    match run_main(parser().get_matches()) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}", e).unwrap();
            std::process::exit(1);
        }
    }
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("tuf")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authenticate and download packages")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .arg({
            let arg = Arg::with_name("home")
             .help("Set the TUF home directory")
             .short("H")
             .long("home")
             .takes_value(true);

            // TODO is this a sane way to do this?
            match *HOME_DIR {
                Some(ref home) => arg.default_value_os(home.as_os_str()),
                None => arg.required(true),
            }
        })
        .subcommand(
            SubCommand::with_name("fetch")
                .about("Fetch a target.")
                .arg(Arg::with_name("target")
                     .help("Name of the target")
                     .takes_value(true)
                     .required(true)
                )
        )

}

fn run_main(matches: ArgMatches) -> Result<()> {
    let home = matches.value_of_os("home").unwrap();

    let mut buf = Vec::new();
    let mut file = File::open(PathBuf::from(home).join("config.toml"))?;
    file.read_to_end(&mut buf)?;
    let cli_config: CliConfig = toml::from_slice(&buf).unwrap(); // TODO unwrap

    if cli_config.config_version > 1 {
        return Err(Error::Opaque(format!("Invalid config version: {}", cli_config.config_version)))
    }

    match matches.subcommand() {
        ("fetch", Some(args)) => fetch_target(home, cli_config, args),
        _ => unreachable!(),
    }
}

fn fetch_target(home: &OsStr, cli_config: CliConfig, args: &ArgMatches) -> Result<()> {
    let mut client = init_client(home, &cli_config)?;
    client.update_local()?;
    client.update_remote()?;
    client.fetch_target(&TargetPath::new(args.value_of("target").unwrap().to_string())?)?;
    Ok(())
}

fn init_client(home: &OsStr, cli_config: &CliConfig) -> Result<Client<Json, FileSystemRepository<Json>, HttpRepository<Json>, DefaultTranslator>> {
    let config = Config::default();
    let local = FileSystemRepository::<Json>::new(PathBuf::from(home));
    let remote = HttpRepository::<Json>::new(cli_config.remote.parse()?, HttpClient::new(), None, None);
    Client::new(config, local, remote)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parser() {
        let _ = parser();
    }
}
