extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
#[cfg(test)]
extern crate tempdir;
extern crate tuf as _tuf;
extern crate url;

use clap::{App, AppSettings, SubCommand, Arg, ArgMatches, ArgGroup};
use std::path::PathBuf;
use _tuf::{Tuf, Config, Error, RemoteRepo};
use url::Url;

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
    let remote = matches.value_of("url").map(|u| RemoteRepo::Http(Url::parse(u).unwrap()))
        .or_else(|| matches.value_of("file").map(|p| RemoteRepo::File(PathBuf::from(p))))
        .unwrap();
    let config = Config::build().remote(remote)
        .local_path(PathBuf::from(matches.value_of("path").unwrap()))
        .init(false)
        .finish()?;

    if let Some(matches) = matches.subcommand_matches("fetch") {
        let tuf = Tuf::new(config)?;
        cmd_fetch(&tuf, matches.value_of("target").unwrap())
    } else if let Some(_) = matches.subcommand_matches("init") {
        let path = PathBuf::from(matches.value_of("path").unwrap());
        cmd_init(&path)
    } else if let Some(_) = matches.subcommand_matches("update") {
        let mut tuf = Tuf::new(config)?;
        cmd_update(&mut tuf)
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        let mut tuf = Tuf::new(config)?;
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
            .validator(url_validator)
            .help("URL of the TUF repo"))
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .takes_value(true)
            .help("Path to the TUF repo (remote)"))
        .arg(Arg::with_name("path")
            .short("p")
            .long("path")
            .takes_value(true)
            .required(true)
            .help("Local path the TUF repo"))
        .group(ArgGroup::with_name("remote_repo")
               .args(&["url", "file"])
               .required(true))
        .subcommand(SubCommand::with_name("fetch").about("Fetch a target")
            .arg(Arg::with_name("target")
                .takes_value(true)
                .required(true)
                .help("The full (non-local) path of the target to verify")))
        .subcommand(SubCommand::with_name("init").about("Initializes a new TUF repo"))
        .subcommand(SubCommand::with_name("update").about("Updates metadata from remotes"))
        .subcommand(SubCommand::with_name("verify")
            .about("Verifies a target")
            .arg(Arg::with_name("target")
                .takes_value(true)
                .required(true)
                .help("The full (non-local) path of the target to verify")))
}

fn cmd_fetch(tuf: &Tuf, target: &str) -> Result<(), Error> {
    tuf.fetch_target(target)
        .map(|_| ())
}

fn cmd_init(local_path: &PathBuf) -> Result<(), Error> {
    Tuf::initialize(local_path)
}

fn cmd_update(tuf: &mut Tuf) -> Result<(), Error> {
    tuf.update()
}

fn cmd_verify(tuf: &mut Tuf, target: &str) -> Result<(), Error> {
    tuf.fetch_target(target)
        .map(|_| ())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::{self, DirBuilder};
    use std::path::{Path, PathBuf};
    use tempdir::TempDir;

    fn vector_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("tuf-test-vectors")
            .join("tuf")
            .join("001")
            .join("repo")
    }

    #[test]
    fn test_clap() {
        let _ = parser();
    }

    fn init_temp(temp: &Path) {
        let dir = PathBuf::from("metadata");
        DirBuilder::new()
            .recursive(true)
            .create(temp.join(dir.clone()))
            .expect(&format!("couldn't create path {}:", temp.join(dir).to_string_lossy()));

        let copy_path = vector_path().join("root.json");
        fs::copy(copy_path,
                 temp.join("metadata").join("root.json"))
            .expect(&format!("copy failed for target"));
    }

    #[test]
    fn run_it() {
        let temp = TempDir::new("rust-tuf").expect("couldn't make temp dir");
        init_temp(temp.path());
        let path = vector_path();
        println!("Temp path: {:?}", temp.path());
        println!("Test path: {:?}", path);

        let matches = parser()
            .get_matches_from_safe(vec!["tuf",
                                        "--file",
                                        &path.to_string_lossy(),
                                        "--path",
                                        temp.path().to_str().expect("path not utf-8"),
                                        "init"])
            .expect("parse error");
        assert_eq!(run_main(matches), Ok(()));

        let matches = parser()
            .get_matches_from_safe(vec!["tuf",
                                        "--file",
                                        &path.to_string_lossy(),
                                        "--path",
                                        temp.path().to_str().expect("path not utf-8"),
                                        "update"])
            .expect("parse error");
        assert_eq!(run_main(matches), Ok(()));

        let matches = parser()
            .get_matches_from_safe(vec!["tuf",
                                        "--file",
                                        &path.to_string_lossy(),
                                        "--path",
                                        temp.path().to_str().expect("path not utf-8"),
                                        "fetch",
                                        "targets/file.txt"])
            .expect("parse error");
        assert_eq!(run_main(matches), Ok(()));

        let matches = parser()
            .get_matches_from_safe(vec!["tuf",
                                        "--file",
                                        &path.to_string_lossy(),
                                        "--path",
                                        temp.path().to_str().expect("path not utf-8"),
                                        "verify",
                                        "targets/file.txt"])
            .expect("parse error");
        assert_eq!(run_main(matches), Ok(()));
    }
}
