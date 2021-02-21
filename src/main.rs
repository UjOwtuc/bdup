use std::collections::HashMap;
use std::{env, error, str};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};

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

fn max_id_less_than<T, I: Iterator<Item = T>>(iterator: &mut I, bound: T) -> Option<T>
    where
        I::Item: Ord,
        T: Clone,
{
    iterator
        .filter(|it| *it < bound)
        .max()
}

fn copy_backup(src_dir: &PathBuf, dest_dir: &PathBuf, backup_name: &str, existing_backups: &mut HashMap<u32, Backup>) -> Result<(), Box<dyn error::Error>> {

    let src = Backup::from_path(src_dir, backup_name)?;
    let base_id: Option<u32> = max_id_less_than(&mut existing_backups.keys().cloned(), src.id);
    let mut base_backup = None;

    if let Some(id) = base_id {
        log::info!("Cloning previous backup {} as base for {}", id, src.id);
        let status = Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg(existing_backups[&id].path())
            .arg(dest_dir.join(backup_name))
            .stdin(Stdio::null())
            .status()?;
        assert!(status.success());

        fs::read_dir(dest_dir.join(backup_name))?
            .map(|result| result.unwrap())
            .filter(|entry| entry.path().is_file())
            .for_each(move |entry| fs::remove_file(entry.path())
                .unwrap_or_else(|_| panic!("Could not remove regular file {:?}", entry.path())));
        existing_backups.get_mut(&id).unwrap().load_checksums()?;
        base_backup = existing_backups.get(&id);
    }
    else {
        log::info!("No suitable base for cloning {}, creating empty directory", src.id);
        let status = Command::new("btrfs")
            .arg("subvolume")
            .arg("create")
            .arg(dest_dir.join(backup_name))
            .stdin(Stdio::null())
            .status()?;
        assert!(status.success());
        fs::create_dir(dest_dir.join(backup_name).join("data"))?;
    }

    let mut copied = Backup::from_path(dest_dir, backup_name)?;
    copied.clone_from(&src, &base_backup)?;
    Ok(())
}

fn duplicate_backups(src: &PathBuf, dest: &PathBuf) -> Result<(), Box<dyn error::Error>> {
    let existing: Vec<String> = get_directories(dest)?
        .iter()
        .filter(|item| dest.join(item).join(".bdup.finished").exists())
        .map(|e| e.to_owned())
        .collect();
    let mut to_copy: Vec<String> = get_directories(src)?
        .iter()
        .filter(|item| src.join(item).join("manifest.gz").exists())
        .filter(|item| ! existing.contains(item))
        .map(|e| e.to_owned())
        .collect();

    // sort in reverse order, so to_copy.pop() returns the oldest backup
    to_copy.sort_unstable_by(|a, b| b.partial_cmp(a).unwrap());

    let mut existing_backups = HashMap::new();
    for name in existing {
        let backup = Backup::from_path(&dest, &name)?;
        existing_backups.insert(backup.id, backup);
    }
    while ! to_copy.is_empty() {
        copy_backup(&src, &dest, &to_copy.pop().unwrap(), &mut existing_backups)?;
    }

    Ok(())
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

    let mut current_backup = 0;
    let total_backups = backups.len();
    if matches.subcommand_matches("verify").is_some() {
        for mut backup in backups {
            current_backup += 1;
            log::info!("Verifying backup {}/{}: {}", current_backup, total_backups, backup.display_name());
            match backup.verify() {
                Ok(0) => log::info!("Backup verified successfully"),
                Ok(errors) => log::info!("Verification found {} errors", errors),
                Err(err) => log::error!("Unable to verify backup: {:?}", err),
            }
        }
    }
    else if let Some(matches) = matches.subcommand_matches("duplicate") {
        duplicate(source_dir, matches.value_of("dest_dir").unwrap());
    }
}

fn duplicate(from: &str, to: &str) {
    let base_dir = PathBuf::from(from);
    let clients = get_directories(&base_dir).expect("Could not get client list");

    let dest_dir = PathBuf::from(to);
    if ! dest_dir.as_path().exists() {
        log::info!("Creating destination directory {:?}", dest_dir);
        fs::create_dir(dest_dir.as_path()).expect("Could not create destination directory");
    }

    let mut client_num = 0;
    let clients_total = clients.len();
    for name in clients {
        client_num += 1;
        log::info!("Duplicating client {}/{}: {}", client_num, clients_total, name);

        if ! dest_dir.join(&name).as_path().exists() {
            log::info!("Creating client destination directory: {:?}", dest_dir.join(&name));
            fs::create_dir(dest_dir.join(&name).as_path())
                .expect("Could not create destination directory");
        }
        duplicate_backups(&base_dir.join(&name), &dest_dir.join(&name))
            .unwrap_or_else(|_| panic!("Error while duplicating backups of {}", name));
    }
}
