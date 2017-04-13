extern crate clap;
extern crate tuf as _tuf;
extern crate url;

use clap::{App, AppSettings, SubCommand, Arg};
use std::path::PathBuf;
use _tuf::{Tuf, Config};
use url::Url;

// TODO logging
// TODO define exit codes. possibly: 0 - success, 1 - unknown failure, 2 - validation failure

fn main() {
    let matches = parser().get_matches();

    // these unwraps are ok because of the validators and settings for `clap`
    let config = Config::build()
        .url(Url::parse(matches.value_of("url").unwrap()).unwrap())
        .local_path(PathBuf::from(matches.value_of("path").unwrap()))
        .finish()
        .expect("bad config"); // TODO don't use expect

    let mut tuf = Tuf::new(config).unwrap(); // TODO unwrap

    let exit = if let Some(_) = matches.subcommand_matches("init") {
        cmd_init(&mut tuf)
    } else if let Some(_) = matches.subcommand_matches("list") {
        cmd_list(&mut tuf)
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        cmd_verify(&mut tuf, matches.value_of("target").unwrap())
    } else {
        unreachable!() // because of AppSettings::SubcommandRequiredElseHelp
    };

    std::process::exit(exit)
}

fn url_validator(url: String) -> Result<(), String> {
    Url::parse(&url)
        .map(|_| ())
        .map_err(|_| "URL was not valid".into())
}

fn parser<'a, 'b>() -> App<'a, 'b> {

    App::new("tuf")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CLI tool for verifying TUF metadata and downloading targets")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .multiple(true)
            .help("Increase the verbosity of output to stderr"))
        .arg(Arg::with_name("url")
            .short("U")
            .long("url")
            .takes_value(true)
            .required(true)
            .validator(url_validator)
            .help("URL of the TUF repo (local or remote)"))
        .arg(Arg::with_name("path")
            .short("p")
            .long("path")
            .takes_value(true)
            .required(true)
            .help("Local path the TUF repo"))
        .subcommand(SubCommand::with_name("init").about("Initializes a new TUF repo"))
        .subcommand(SubCommand::with_name("list").about("Lists available targets"))
        .subcommand(SubCommand::with_name("verify").about("Verifies a target")
                    .arg(Arg::with_name("target")
                         .takes_value(true)
                         .required(true)
                         .help("The full (non-local) path of the target to verify")))
}

fn cmd_init(tuf: &mut Tuf) -> i32 {
    match tuf.initialize() {
        Ok(()) => 0,
        Err(_) => 1, // TODO error message
    }
}

fn cmd_list(tuf: &mut Tuf) -> i32 {
    let mut targets = tuf.list_targets();
    targets.sort();

    for target in targets.iter() {
        println!("{}", target);
    }
    0
}

fn cmd_verify(tuf: &mut Tuf, target: &str) -> i32 {
    match tuf.verify_target(target) {
        Ok(()) => 0,
        Err(_) => 1, // TODO error message
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn clap() {
        let _ = parser();
    }
}
