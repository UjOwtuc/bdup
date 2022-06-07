use derive_more::{Display, Error};
use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;

use burp::backup::Backup;

fn init_args_parser() -> clap::App<'static, 'static> {
    clap::App::new("bverify")
        .version(clap::crate_version!())
        .author("Karsten Borgwaldt <bdup@spambri.de>")
        .about("Verifies burp backups")
        .arg(
            clap::Arg::with_name("log_level")
                .short("l")
                .long("log-level")
                .help("Set log level")
                .possible_values(&["trace", "debug", "info", "warn", "error", "off"])
                .case_insensitive(true)
                .value_name("LEVEL")
                .default_value("info")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("iothreads")
                .short("t")
                .long("io-threads")
                .help("Thread pool size for I/O operations (i.e. copying files)")
                .value_name("NUM")
                .takes_value(true)
                .empty_values(false)
                .default_value("4")
                .validator(|v: String| -> Result<(), String> {
                    if let Ok(num) = v.parse::<usize>() {
                        if num > 0 {
                            return Ok(());
                        }
                    }
                    Err("Needs to an integer greater than zero".to_string())
                }),
        )
        .arg(
            clap::Arg::with_name("backup")
                .help("Directories of backups to verify")
                .value_name("DIR")
                .takes_value(true)
                .empty_values(false)
                .multiple(true)
                .required(true),
        )
}

#[derive(Debug, Display, Error)]
#[display(fmt = "{}/{} backups failed to verify", errors, total)]
struct VerifyError {
    errors: usize,
    total: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = init_args_parser().get_matches();

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::from_str(
            matches.value_of("log_level").unwrap(),
        )?)
        .chain(std::io::stdout())
        .apply()
        .unwrap_or_else(|err| panic!("Log init failed: {:?}", err));

    let mut errors: usize = 0;
    let mut total_backups = 0;
    let num_threads = matches.value_of("iothreads").unwrap().parse::<usize>()?;
    for path in matches.values_of("backup").unwrap() {
        total_backups += 1;
        match Backup::from_path(&PathBuf::from(path)) {
            Ok(mut backup) => {
                if let Err(err) = backup.verify(num_threads) {
                    errors += 1;
                    log::error!(
                        "Verify of backup {} failed: {:?}",
                        backup.path().display(),
                        err
                    );
                }
            }
            Err(err) => {
                log::error!("Path {} does not seem to be a backup: {:?}", path, err);
                errors += 1;
            }
        }
    }

    if errors > 0 {
        Err(Box::new(VerifyError {
            errors,
            total: total_backups,
        }))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn require_positional_args() {
        assert!(init_args_parser()
            .get_matches_from_safe(vec!["bverify"])
            .is_err());
    }

    #[test]
    fn single_positional_arg() {
        let matches = init_args_parser().get_matches_from(vec!["bverify", "single dir"]);
        let values: Vec<&str> = matches.values_of("backup").unwrap().collect();
        assert_eq!(values, ["single dir"].to_vec());
    }

    #[test]
    fn multiple_positional_args() {
        let matches = init_args_parser().get_matches_from(vec!["bverify", "dir1", "dir 2", "dir3"]);
        let values: Vec<&str> = matches.values_of("backup").unwrap().collect();
        assert_eq!(values, ["dir1", "dir 2", "dir3"].to_vec());
    }

    #[test]
    fn arg_log_level_setting() {
        let res = init_args_parser().get_matches_from(vec!["bverify", "-l", "debug", "dir"]);
        assert_eq!(res.value_of("log_level"), Some("debug"));
    }

    #[test]
    fn arg_log_level_validator() {
        let res =
            init_args_parser().get_matches_from_safe(vec!["bverify", "-l", "something", "dir"]);
        assert!(res.is_err());
    }

    #[test]
    fn arg_iothreads_setting() {
        let res = init_args_parser().get_matches_from(vec!["bverify", "-t", "5781", "dir"]);
        assert_eq!(res.value_of("iothreads"), Some("5781"));
    }

    #[test]
    fn arg_iothreads_validator() {
        assert!(init_args_parser()
            .get_matches_from_safe(vec!["bverify", "--io-threads", "no int", "dir"])
            .is_err());
    }
}
