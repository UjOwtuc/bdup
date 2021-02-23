use std::{env, str};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::os::unix::ffi::OsStrExt;

mod manifest;
mod backup;
use backup::Backup;

fn get_directories(base_dir: &Path) -> io::Result<Vec<String>> {
    let mut dirs = Vec::new();
    for dir_entry in fs::read_dir(base_dir)? {
        let entry = dir_entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                dirs.push(name.to_owned());
            }
        }
    }

    Ok(dirs)
}

fn main() {
    let matches = clap::App::new("bdup")
        .version("0.1.0")
        .author("Karsten Borgwaldt <bdup@spambri.de>")
        .about("Duplicates burp backups")
        .arg(clap::Arg::with_name("source")
            .short("s")
            .long("source")
            .help("Source backup directory")
            .takes_value(true))
        .arg(clap::Arg::with_name("log_level")
            .short("l")
            .long("log-level")
            .help("Set log level (trace, debug, info, warn, error)")
            .takes_value(true))
        .arg(clap::Arg::with_name("clients")
            .short("c")
            .long("clients")
            .help("Comma separated list of clients to work on")
            .takes_value(true))
        .arg(clap::Arg::with_name("single_backup")
            .short("S")
            .long("single-backup")
            .help("Operate on given single backup path only")
            .conflicts_with("clients")
            .conflicts_with("source_dir")
            .takes_value(true))
        .subcommand(clap::SubCommand::with_name("verify")
            .about("Verify integrity of backups"))
        .subcommand(clap::SubCommand::with_name("duplicate")
            .about("Duplicate backups")
            .arg(clap::Arg::with_name("dest_dir")
                .short("d")
                .long("dest-dir")
                .help("Destination directory")
                .takes_value(true)
                .required(true)))
        .get_matches();

    let source_dir = matches.value_of("source").unwrap_or("/var/spool/burp");
    let clients = if let Some(client_list) = matches.value_of("clients") {
        client_list.split(',').map(String::from).collect()
    }
    else {
        get_directories(&PathBuf::from(&source_dir)).expect("Could not get client list")
    };

    if let Some(level) = matches.value_of("log_level") {
        env::set_var("RUST_LOG", level);
    }
    pretty_env_logger::init();

    let mut backups = Vec::new();
    if let Some(path) = matches.value_of("single_backup") {
        let path = PathBuf::from(path);
        let parent = path.parent().unwrap();
        let name = str::from_utf8(path.file_name().unwrap().as_bytes()).unwrap();
        backups.push(Backup::from_path(parent, name).unwrap());
    }
    else {
        let source_dir = PathBuf::from(source_dir);
        for client in clients {
            backups.extend(backup::find_backups(&source_dir.join(client)).unwrap());
        }
    }

    if matches.subcommand_matches("duplicate").is_some() {
        let dest_dir = matches.subcommand_matches("duplicate").unwrap().value_of("dest_dir").unwrap();
        if ! PathBuf::from(dest_dir).exists() {
            fs::create_dir(dest_dir).unwrap_or_else(|err| panic!("Could not create destination directory: {:?}", err));
        }
    }

    let mut current_backup = 0;
    let total_backups = backups.len();
    for mut backup in backups {
        current_backup += 1;
        if matches.subcommand_matches("verify").is_some() {
            log::info!("Verifying backup {}/{}: {}", current_backup, total_backups, backup.display_name());
            match backup.verify() {
                Ok(0) => log::info!("Backup verified successfully"),
                Ok(errors) => log::info!("Verification found {} errors", errors),
                Err(err) => log::error!("Unable to verify backup: {:?}", err),
            }
        }
        else if let Some(matches) = matches.subcommand_matches("duplicate") {
            let dest_dir = matches.value_of("dest_dir").unwrap();
            log::info!("Duplicating backup {}/{} from {} to {}", current_backup, total_backups, backup.display_name(), dest_dir);

            let mut dest = Backup::new(&PathBuf::from(dest_dir).join(backup.client()), &backup.dirname());
            dest.clone_from(&backup)
                .unwrap_or_else(|err| panic!("Cloning of backup {} failed: {:?}", backup.display_name(), err));
        }
    }
}

