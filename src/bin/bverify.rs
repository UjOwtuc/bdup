use clap::Parser;
use derive_more::{Display, Error};
use std::error::Error;
use std::path::PathBuf;

use burp::backup::Backup;

#[derive(Parser, Debug)]
struct Args {
    /// Set log level
    ///
    /// Possible values are: off, error, warn, info, debug, trace
    #[arg(short, long, value_enum, value_name = "LEVEL")]
    log_level: Option<log::LevelFilter>,

    /// Thread pool size for I/O operations (i.e. copying files)
    #[arg(short = 't', long, default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..))]
    iothreads: u64,

    /// Directories of backups to verify
    ///
    /// At least one directory must be specified. Backups are verified in the given order.
    #[arg(required(true))]
    backup: Vec<String>,
}

#[derive(Debug, Display, Error)]
#[display(fmt = "{}/{} backups failed to verify", errors, total)]
struct VerifyError {
    errors: usize,
    total: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Args::parse();

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
        .level(matches.log_level.unwrap_or(log::LevelFilter::Info))
        .chain(std::io::stdout())
        .apply()
        .unwrap_or_else(|err| panic!("Log init failed: {:?}", err));

    let mut errors: usize = 0;
    let mut total_backups = 0;
    let num_threads = matches.iothreads;
    for path in &matches.backup {
        total_backups += 1;
        match Backup::from_path(&PathBuf::from(path)) {
            Ok(mut backup) => {
                if let Err(err) = backup.verify(num_threads.try_into()?) {
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
