use std::error::Error;
use std::fmt;
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
                .required(true),
        )
}

#[derive(Debug)]
struct VerifyError {
    errors: usize,
    total: usize,
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} backups failed to verify", self.errors, self.total)
    }
}
impl Error for VerifyError {}

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
        match Backup::new(&PathBuf::from(path)) {
            Ok(mut backup) => {
                if let Err(err) = backup.verify(num_threads) {
                    errors += 1;
                    log::error!(
                        "Verify of backup {} failed: {:?}",
                        backup.path.display(),
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
