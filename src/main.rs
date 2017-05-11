extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
#[cfg(test)]
extern crate tempdir;
extern crate tuf as _tuf;
extern crate url;

use clap::{App, AppSettings, SubCommand, Arg, ArgMatches};
use std::path::PathBuf;
use _tuf::{Tuf, Config, Error};
use url::Url;

// TODO logging

fn main() {
    let matches = parser().get_matches();
    env_logger::init().unwrap();

    match run_main(matches) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            error!("{:?}", e);
            std::process::exit(1);
        }
    }
}

fn run_main(matches: ArgMatches) -> Result<(), Error> {
    let config = Config::build()
        .url(Url::parse(matches.value_of("url").unwrap()).unwrap())
        .local_path(PathBuf::from(matches.value_of("path").unwrap()))
        .finish()
        .expect("bad config"); // TODO don't use expect

    if let Some(_) = matches.subcommand_matches("init") {
        let path = PathBuf::from(matches.value_of("path").unwrap());
        cmd_init(&path)
    } else if let Some(_) = matches.subcommand_matches("list") {
        let mut tuf = Tuf::new(config).unwrap(); // TODO unwrap
        cmd_list(&mut tuf)
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        let mut tuf = Tuf::new(config).unwrap(); // TODO unwrap
        cmd_verify(&mut tuf, matches.value_of("target").unwrap())
    } else {
        unreachable!() // because of AppSettings::SubcommandRequiredElseHelp
    }
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
        .subcommand(SubCommand::with_name("verify")
            .about("Verifies a target")
            .arg(Arg::with_name("target")
                .takes_value(true)
                .required(true)
                .help("The full (non-local) path of the target to verify")))
}

fn cmd_init(local_path: &PathBuf) -> Result<(), Error> {
    Tuf::initialize(local_path)
}

fn cmd_list(tuf: &mut Tuf) -> Result<(), Error> {
    let mut targets = tuf.list_targets();
    targets.sort();

    for target in targets.iter() {
        println!("{}", target);
    }

    Ok(())
}

fn cmd_verify(tuf: &mut Tuf, target: &str) -> Result<(), Error> {
    tuf.verify_target(target)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::{self, DirBuilder};
    use std::path::Path;
    use tempdir::TempDir;

    #[test]
    fn test_clap() {
        let _ = parser();
    }

    fn init_temp(temp: &Path) {
        let vector_path = "./tests/tuf-test-vectors/vectors/001";

        for dir in vec!["metadata/latest", "metadata/archive", "targets"].iter() {
            DirBuilder::new()
                .recursive(true)
                .create(temp.join(dir))
                .expect(&format!("couldn't create path {}:", dir));
        }

        for file in vec!["root.json", "targets.json", "timestamp.json", "snapshot.json"].iter() {
            fs::copy(format!("{}/repo/{}", vector_path, file),
                     temp.join("metadata").join("latest").join(file))
                .expect(&format!("copy failed: {}", file));
        }

        fs::copy(format!("{}/repo/targets/file.txt", vector_path),
                 temp.join("targets").join("file.txt"))
            .expect(&format!("copy failed for target"));
    }

    #[test]
    fn run_verify() {
        let temp = TempDir::new("rust-tuf").expect("couldn't make temp dir");
        init_temp(temp.path());

        let matches = parser()
            .get_matches_from_safe(vec!["tuf",
                                        "--url",
                                        "file:///tmp",
                                        "--path",
                                        temp.path().to_str().expect("path not utf-8"),
                                        "verify",
                                        "targets/file.txt"])
            .expect("parse error");

        assert_eq!(run_main(matches), Ok(()));
    }
}
