use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::io;
use std::fs;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::ffi::{OsStr, OsString};
use std::error::Error;
use std::process::{Command, Stdio};
use std::cmp::Ordering;
use flate2::read::GzDecoder;
use threadpool::ThreadPool;

use crate::manifest;

fn visit_dirs(dir: &Path, cb: &dyn Fn(&fs::DirEntry) -> Result<(), Box<dyn Error>>) -> Result<(), Box<dyn Error>> {
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

pub trait Backup : Sync + Send {
    fn id(&self) -> u64;
    fn dir_name(&self) -> String;
    fn local_path(&self) -> &Path;
    fn fetch_temporary(&self, prefix: Option<&str>, path: &OsStr) -> io::Result<PathBuf>;
    fn fetch_file(&self, prefix: Option<&str>, path: &OsStr, dest: &Path) -> io::Result<u64>;
    fn load_checksums(&mut self) -> Result<(), Box<dyn Error>>;
    fn forget_checksums(&mut self);

    #[inline]
    fn metadata_files() -> &'static [&'static str] where Self: Sized {
        &["manifest.gz", "log.gz", "backup_stats", "timestamp", "incexc"]
    }

    fn manifest_reader(&self) -> Result<io::BufReader<flate2::read::GzDecoder<fs::File>>, Box<dyn Error>> {
        let manifest = fs::File::open(self.fetch_temporary(None, &OsString::from("manifest.gz"))?)?;
        let gz = GzDecoder::new(manifest);
        Ok(io::BufReader::new(gz))
    }

    fn is_finished(&self) -> bool;
    fn is_local(&self) -> bool;
    fn get_checksums(&self) -> &HashMap<PathBuf, String>;
}

pub struct LocalBackup {
    path: PathBuf,
    id: u64,
    timestamp: String,
    checksums: HashMap<PathBuf, String>,
}

impl LocalBackup {
    pub fn new(path: &Path) -> Self {
        let dir = path.file_name().expect("Invalid path for local backup: no file_name component").to_string_lossy();
        let id = dir[0..7].parse::<u64>().unwrap_or_else(|err| panic!("Invalid path for local backup: could not parse id from directory name: {:?}", err));
        let timestamp = dir[8..].to_owned();
        Self {
            path: path.to_owned(),
            id,
            timestamp,
            checksums: HashMap::new(),
        }
    }

    /*
    pub fn delete(&mut self) -> io::Result<()> {
        unimplemented!();
    }
    */

    fn file_path(&self, prefix: Option<&str>, path: &OsStr) -> io::Result<PathBuf> {
        let mut real_path = PathBuf::from(&self.path);
        if let Some(prefix) = prefix {
            real_path = real_path.join(prefix);
        }
        real_path = real_path.join(path);
        let _attr = real_path.metadata()?;
        Ok(real_path)
    }

    fn create_volume(&self, base_backup: &Option<&Arc<dyn Backup>>) -> Result<(), Box<dyn Error>> {
        if let Some(parent_dir) = self.path.parent() {
            if ! parent_dir.exists() {
                fs::create_dir(parent_dir)?;
            }
        }

        if let Some(base_backup) = base_backup {
            log::info!("Cloning previous backup {:?}", base_backup.local_path());
            let status = Command::new("btrfs")
                .arg("subvolume")
                .arg("snapshot")
                .arg(base_backup.local_path().to_owned())
                .arg(self.path.to_owned())
                .stdin(Stdio::null())
                .status()?;
            assert!(status.success());

            fs::read_dir(self.path.to_owned())?
                .map(|result| result.unwrap())
                .filter(|entry| entry.path().is_file())
                .for_each(move |entry| fs::remove_file(entry.path())
                    .unwrap_or_else(|_| panic!("Could not remove regular file {:?}", entry.path())));
        }
        else {
            log::info!("Creating empty volume");
            let status = Command::new("btrfs")
                .arg("subvolume")
                .arg("create")
                .arg(self.path.to_owned())
                .stdin(Stdio::null())
                .status()?;
            assert!(status.success());
            fs::create_dir(self.path.join("data"))?;
        }
        fs::File::create(self.path.join(".bdup.partial"))?;
        Ok(())
    }

    pub fn clone_from(&mut self, base_backup: &Option<&Arc<dyn Backup>>, src: &Arc<dyn Backup>) -> Result<(), Box<dyn Error>> {
        if self.is_finished() {
            log::info!("Cloning to {:?} already finished. Skipping", self.path);
            return Ok(());
        }

        // TODO: make sure, base_backup has loaded checksums
        self.create_volume(base_backup)?;

        let worker_pool = ThreadPool::new(2);
        let (tx, rx) = channel();

        let mut files_total = 0;
        let mut files_from_base = 0;

        log::info!("Fetching metadata");
        for filename in Self::metadata_files() {
            let dest_path = self.path.join(filename);
            match src.fetch_file(None, OsStr::new(filename), &dest_path) {
                Ok(_) => (),
                Err(error) => {
                    log::error!("Could not fetch metadata file {}: {:?}", filename, error);
                    return Err(Box::new(error));
                },
            }
        }

        log::info!("Starting data transfers");
        let mut files_in_manifest = HashSet::new();
        manifest::read_manifest(&mut self.manifest_reader()?, &mut |entry: &manifest::ManifestEntry| {
            if let Some(data) = &entry.data {
                files_in_manifest.insert(data.path.to_owned());

                files_total += 1;
                let data_path = data.path.to_owned();
                let mut copied = false;
                if let Some(base) = &base_backup {
                    if let Some(base_md5) = &base.get_checksums().get(&data_path) {
                        if **base_md5 == data.md5 {
                            files_from_base += 1;
                            copied = true;
                        }
                    }
                }
                if ! copied {
                    let dest_path = self.path.join("data").join(&data_path);
                    let file_size = data.size;
                    let tx = tx.clone();
                    let src_clone = src.clone();
                    worker_pool.execute(move || {
                        tx.send(match src_clone.fetch_file(Some("data"), &data_path.as_os_str(), &dest_path) {
                            Ok(_) => {
                                Ok((data_path, file_size))
                            },
                            Err(error) => {
                                Err((data_path, format!("{}", error)))
                            }
                        }).unwrap();
                    });
                }
            }
            Ok(())
        })?;
        drop(tx);

        log::info!("Waiting for queued transfers to finish");
        let mut files_ok = 0;
        let mut transfer_size = 0;
        for result in rx.iter() {
            match result {
                Ok((_, size)) => {
                    files_ok += 1;
                    transfer_size += size;
                },
                Err((path, error)) => log::error!("Could not fetch file {:?}: {:?}", path, error),
            }
        }

        if base_backup.is_some() {
            log::info!("Removing superfluous files (cloned from base, not in this backup)");
            let data_path = self.path.join("data");
            visit_dirs(&data_path, &|entry: &fs::DirEntry| -> Result<(), Box<dyn Error>> {
                let path = entry.path().strip_prefix(&data_path)?.to_owned();
                if ! files_in_manifest.contains(&path) {
                    fs::remove_file(data_path.join(entry.path()))?;

                    for parent in entry.path().parent().unwrap().ancestors() {
                        if parent.read_dir()?.next().is_none() {
                            fs::remove_dir(parent)?;
                        }
                    }
                }
                Ok(())
            })?;
        }

        let errors = files_total - files_ok - files_from_base;
        if errors == 0 {
            log::info!("Cloning finished successfully: {} files total, {} from base backup, {} bytes transferred", files_total, files_from_base, transfer_size);
            fs::remove_file(self.path.join(".bdup.partial"))?;
            let status = Command::new("btrfs")
                .arg("property")
                .arg("set")
                .arg(self.path.to_owned())
                .arg("ro")
                .arg("true")
                .stdin(Stdio::null())
                .status()?;
            assert!(status.success());
        }
        else {
            log::warn!("Cloning finished with errors: {}/{} files were successful, {} from base backup, {} bytes transferred", files_from_base + files_ok, files_total, files_from_base, transfer_size);
        }
        Ok(())
    }
}

impl Backup for LocalBackup {
    fn id(&self) -> u64 {
        self.id
    }

    fn local_path(&self) -> &Path {
        &self.path
    }

    fn dir_name(&self) -> String {
        format!("{:07} {}", self.id, self.timestamp)
    }

    fn fetch_temporary(&self, prefix: Option<&str>, path: &OsStr) -> io::Result<PathBuf> {
        self.file_path(prefix, path)
    }

    fn fetch_file(&self, prefix: Option<&str>, path: &OsStr, dest: &Path) -> io::Result<u64> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(self.file_path(prefix, path)?, dest)
    }

    fn load_checksums(&mut self) -> Result<(), Box<dyn Error>> {
        if self.checksums.is_empty() {
            log::info!("Loading checksums from backup {:?}", self.path);
            let mut reader = self.manifest_reader()?;

            manifest::read_manifest(&mut reader, &mut |entry: &manifest::ManifestEntry| {
                if let Some(data) = &entry.data {
                    self.checksums.insert(data.path.to_owned(), data.md5.to_owned());
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    fn forget_checksums(&mut self) {
        self.checksums = HashMap::new();
    }

    fn is_finished(&self) -> bool {
        self.path.join("manifest.gz").exists() && ! self.path.join(".bdup.partial").exists()
    }

    fn is_local(&self) -> bool {
        true
    }

    fn get_checksums(&self) -> &HashMap<PathBuf, String> {
        &self.checksums
    }
}

impl Eq for dyn Backup {}

impl Ord for dyn Backup {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(&other.id())
    }
}

impl PartialOrd for dyn Backup {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for dyn Backup {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

/*
pub struct RemoteBackup {
    url: String,
    id: u64,
    timestamp: String,
    checksums: HashMap<PathBuf, String>,
}
*/

