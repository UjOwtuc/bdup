use std::collections::HashMap;
use std::{env, error, str};
use std::error::Error;
use std::fs;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use std::process::{Command, Stdio};
use md5;
use log;
use clap;

mod manifest;
use manifest::ManifestEntry;


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

fn calc_md5<T: io::Read>(reader: &mut T) -> io::Result<md5::Digest> {
    let mut ctx = md5::Context::new();
    let mut buf = vec![0_u8; 4096];
    loop {
        let len = reader.read(&mut buf)?;
        ctx.consume(&buf[0..len]);
        if len == 0 {
            break;
        }
    }
    Ok(ctx.compute())
}

struct Backup {
    base_dir: PathBuf,
    id: u32,
    timestamp: String,
    checksums: HashMap<PathBuf, String>
}

impl Backup {
    fn from_path(path: &Path, name: &str) -> Result<Self, Box<dyn error::Error>> {
        if path.join(name).join("manifest.gz").exists() {
            let id = name[0..7].parse::<u32>()?;
            Ok(Self{ base_dir: PathBuf::from(path), id: id, timestamp: name[8..].to_owned(), checksums: HashMap::new() })
        }
        else {
            Err(Box::new(manifest::ManifestReadError::new("no manifest.gz in given path")))
        }
    }

    fn path(&self) -> PathBuf {
        self.base_dir.join(format!("{:07} {}", self.id, self.timestamp))
    }

    fn load_checksums(&mut self) -> Result<(), Box<dyn Error>> {
        if self.checksums.is_empty() {
            log::info!("Loading checksums from backup {:?}", self.path());
            let manifest = fs::File::open(self.path().join("manifest.gz"))?;
            let gz = GzDecoder::new(manifest);
            let mut reader = BufReader::new(gz);

            manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
                if let Some(md5) = &entry.md5 {
                    self.checksums.insert(PathBuf::from(&entry.path), md5.to_owned());
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    fn fetch_file(&self, entry: &ManifestEntry, src: &Backup, base: &Option<&Backup>) -> Result<(), Box<dyn Error>> {
        if let Some(base_backup) = base {
            if let Some(base_md5) = &base_backup.checksums.get(&entry.path) {
                let md5 = entry.md5.as_ref().unwrap();
                if md5 == *base_md5 {
                    return Ok(())
                }
            }
        }
        if let Some(path) = &entry.data_path {
            let rel_path = PathBuf::from("data").join(&path);
            fs::copy(src.path().join(&rel_path), self.path().join(&rel_path))?;
        }
        Ok(())
    }

    fn clone_from(&mut self, src: &Backup, base: &Option<&Backup>) -> Result<(), Box<dyn Error>> {
        if let Some(base_backup) = base {
            assert!(! base_backup.checksums.is_empty());
        }

        fs::copy(src.path().join("manifest.gz"), self.path().join("manifest.gz"))?;

        let manifest = fs::File::open(self.path().join("manifest.gz"))?;
        let gz = GzDecoder::new(manifest);
        let mut reader = BufReader::new(gz);
        manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
            if let Some(_) = &entry.data_path {
                self.fetch_file(entry, src, base)?;
            }
            Ok(())
        })?;

        self.verify()?;
        fs::File::create(self.path().join(".bdup.finished"))?;
        Ok(())
    }

    fn verify(&mut self) -> Result<(), Box<dyn error::Error>> {
        let data_path = self.path().join("data");
        let manifest = fs::File::open(self.path().join("manifest.gz"))?;
        let gz = GzDecoder::new(manifest);
        let mut reader = BufReader::new(gz);
        manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
            if let Some(checksum) = &entry.md5 {
                let mut input = fs::File::open(data_path.join(entry.data_path.as_ref().unwrap()))?;
                let digest = if entry.stat.compression > 0 {
                    calc_md5(&mut GzDecoder::new(input))
                }
                else {
                    calc_md5(&mut input)
                }?;
                let digest = format!("{:x}", digest);
                if **checksum != digest {
                    log::error!("Incorrect checksum: {:?} expected: {}, computed: {}", entry.path, checksum, digest);
                }
            }
            Ok(())
        })?;

        visit_dirs(&data_path, &|entry: &fs::DirEntry| -> Result<(), Box<dyn error::Error>> {
            let path = entry.path().strip_prefix(&data_path)?.to_owned();
            if let Some(checksum) = &self.checksums.get(&path) {
                let mut ctx = md5::Context::new();
                let mut input = fs::File::open(entry.path())?;
                let mut buf = vec![0_u8; 4096];
                while let Ok(len) = input.read(&mut buf) {
                    ctx.consume(&buf[0..len]);
                    if len != 4096 {
                        break;
                    }
                }
                let digest = format!("{:x}", ctx.compute());
                if **checksum != digest {
                    log::error!("Incorrect checksum: {:?} expected: {}, computed: {}", path, checksum, digest);
                }
            }
            else {
                log::info!("Found superfluous file while validating: {:?}", path);
            }
            Ok(())
        })?;
        Ok(())
    }
}

fn visit_dirs(dir: &Path, cb: &dyn Fn(&fs::DirEntry) -> Result<(), Box<dyn error::Error>>) -> Result<(), Box<dyn error::Error>> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry)?;
            }
        }
    }
    Ok(())
}

fn max_id_less_than<T, I: Iterator<Item = T>>(iterator: &mut I, bound: T) -> Option<T>
    where
        I::Item: Ord,
        T: Clone,
{
    let result = iterator
        .filter(|it| *it < bound)
        .max()
        .clone();

    result
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
                .expect(&format!("Could not remove regular file {:?}", entry.path())));
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
    while to_copy.len() > 0 {
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

    if let Some(level) = matches.value_of("log_level") {
        env::set_var("RUST_LOG", level);
    }
    pretty_env_logger::init();

    println!("source dir: {}", source_dir);

    if let Some(_) = matches.subcommand_matches("verify") {
        verify(source_dir);
    }
    else if let Some(matches) = matches.subcommand_matches("duplicate") {
        duplicate(source_dir, matches.value_of("dest_dir").unwrap());
    }
}

fn verify_backups(base_dir: &Path) -> Result<(), Box<dyn Error>> {
    for dir in get_directories(base_dir)? {
        log::info!("Verifying backup {:?}", dir);
        let mut backup = Backup::from_path(base_dir, &dir)?;
        backup.verify()?;
    }
    Ok(())
}

fn verify(source_dir: &str) {
    let base_dir = PathBuf::from(source_dir);
    let clients = get_directories(&base_dir).expect("Could not get client list");

    let mut client_num = 0;
    let clients_total = clients.len();
    for name in clients {
        client_num += 1;
        log::info!("Verifying client {}/{}: {}", client_num, clients_total, &name);

        verify_backups(&base_dir.join(&name)).expect(&format!("Verify failed for client {}", name));
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
            .expect(&format!("Error while duplicating backups of {}", name));
    }
}
