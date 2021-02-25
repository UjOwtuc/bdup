use std::collections::{HashMap, HashSet};
use std::str;
use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::sync::Arc;
use std::error::Error;
use std::ffi::OsStr;
use std::sync::mpsc::channel;
use std::cmp::Ordering;
use std::process::{Command, Stdio};
use flate2::read::GzDecoder;
use threadpool::ThreadPool;

use crate::manifest;
use crate::manifest::ManifestEntry;

pub fn find_backups(path: &Path) -> Result<Vec<Backup>, Box<dyn Error>>
{
    log::debug!("finding backups in {}", path.display());
    let mut backups = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().join("manifest.gz").exists() {
            let name = &entry.file_name().to_str().unwrap().to_owned();
            match Backup::from_path(path, &name) {
                Ok(backup) => backups.push(backup),
                Err(error) => log::debug!("Skipping {}/{}: {}", path.display(), name, error),
            }
        }
        else {
            log::debug!("Skipping {}: no manifest", entry.path().display());
        }
    }
    Ok(backups)
}

enum VerifyResult {
    Ok,
    ChecksumMismatch(String),
    Error(String),
}

struct VerifyFileResult {
    path: PathBuf,
    md5: String,
    result: VerifyResult
}

#[derive(Eq)]
pub struct Backup {
    pub base_dir: PathBuf,
    pub id: u32,
    timestamp: String,
    checksums: HashMap<PathBuf, String>
}

impl Backup {
    #[inline]
    pub fn metadata_files() -> &'static [&'static str] {
        &["manifest.gz", "log.gz", "backup_stats", "timestamp", "incexc"]
    }

    fn parse_name(name: &str) -> Result<(u32, String), Box<dyn Error>> {
        let id = name[0..7].parse::<u32>()?;
        Ok((id, name[8..].to_owned()))
    }

    pub fn from_path(path: &Path, name: &str) -> Result<Self, Box<dyn Error>> {
        if path.join(name).join("manifest.gz").exists() {
            let id = name[0..7].parse::<u32>()?;
            Ok(Self{ base_dir: PathBuf::from(path), id, timestamp: name[8..].to_owned(), checksums: HashMap::new() })
        }
        else {
            Err(Box::new(manifest::ManifestReadError::new("no manifest.gz in given path")))
        }
    }

    pub fn new(base_dir: &Path, name: &str) -> Self {
        let (id, timestamp) = Self::parse_name(name).unwrap();
        Self{ base_dir: base_dir.to_owned(), id, timestamp, checksums: HashMap::new() }
    }

    pub fn display_name(&self) -> String {
        format!("client={}, id={}, timestamp={}", self.client(), self.id, self.timestamp)
    }

    pub fn client(&self) -> String {
        self.base_dir.file_name().unwrap().to_string_lossy().to_string()
    }

    pub fn dirname(&self) -> String {
        format!("{:07} {}", self.id, self.timestamp)
    }

    pub fn path(&self) -> PathBuf {
        self.base_dir.join(self.dirname())
    }

    fn manifest_reader(&self) -> Result<io::BufReader<flate2::read::GzDecoder<fs::File>>, Box<dyn Error>> {
        let manifest = fs::File::open(self.path().join("manifest.gz"))?;
        let gz = GzDecoder::new(manifest);
        Ok(io::BufReader::new(gz))
    }

    pub fn load_checksums(&mut self) -> Result<(), Box<dyn Error>> {
        if self.checksums.is_empty() {
            log::info!("Loading checksums from backup {:?}", self.path());
            let mut reader = self.manifest_reader()?;

            manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
                if let Some(data) = &entry.data {
                    self.checksums.insert(data.path.to_owned(), data.md5.to_owned());
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    pub fn fetch_file(&self, prefix: Option<&str>, path: &OsStr, dest: &Path) -> io::Result<u64> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::copy(match prefix {
            Some(prefix) => self.path().join(prefix),
            None => self.path(),
        }.join(path), dest)
    }

    pub fn sibling_backups(&self) -> Result<Vec<Backup>, Box<dyn Error>> {
        let mut backups = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            if entry.path().join(".bdup.partial").exists() {
                log::debug!("not considering {} as sibling, because .bdup.partial stamp exists", entry.path().display());
            }
            else {
                let name = &entry.file_name().to_str().unwrap().to_owned();
                match Backup::from_path(&self.base_dir, &name) {
                    Ok(backup) => backups.push(backup),
                    Err(error) => log::debug!("Ignoring {}, because it is no backup: {}", name, error),
                }
            }
        }
        Ok(backups)
    }

    pub fn find_clone_base(&self) -> Option<Backup> {
        if let Ok(siblings) = self.sibling_backups() {
            siblings.into_iter()
                .filter(|backup| backup.id < self.id)
                .max()
        }
        else {
            None
        }
    }

    pub fn is_finished(&self) -> bool {
        let path = self.path();
        path.exists() && path.join("manifest.gz").exists() && ! self.path().join(".bdup.partial").exists()
    }

    pub fn clone_from(&mut self, src: &Arc<Backup>) -> Result<(), Box<dyn Error>> {
        if self.is_finished() {
            log::info!("Cloning to {:?} already finished. Skipping", self.path());
            return Ok(());
        }

        let base = if let Some(mut base_backup) = self.find_clone_base() {
            log::info!("Using {:?} as base for {:?}", base_backup.path(), self.path());
            base_backup.load_checksums()?;
            Some(base_backup)
        }
        else {
            log::info!("No suitable base for cloning into {:?}", self.path());
            None
        };

        self.create_volume(&base)?;

        let worker_pool = ThreadPool::new(2);
        let (tx, rx) = channel();

        let mut files_total = 0;
        let mut files_from_base = 0;

        log::info!("Fetching metadata");
        for filename in Self::metadata_files() {
            let dest_path = self.path().join(filename);
            match src.fetch_file(None, OsStr::new(filename), &dest_path) {
                Ok(_) => (),
                Err(error) => {
                    log::error!("Could not fetch metadata file {}: {:?}", filename, error);
                    return Err(Box::new(error));
                },
            }
        }

        log::info!("Starting data transfers");
        manifest::read_manifest(&mut self.manifest_reader()?, &mut |entry: &ManifestEntry| {
            if let Some(data) = &entry.data {
                files_total += 1;
                let data_path = data.path.to_owned();
                let mut copied = false;
                if let Some(base) = &base {
                    if let Some(base_md5) = &base.checksums.get(&data_path) {
                        if **base_md5 == data.md5 {
                            files_from_base += 1;
                            copied = true;
                        }
                    }
                }
                if ! copied {
                    let dest_path = self.path().join("data").join(&data_path);
                    let tx = tx.clone();
                    let src_clone = src.clone();
                    worker_pool.execute(move || {
                        match src_clone.fetch_file(Some("data"), &data_path.as_os_str(), &dest_path) {
                            Ok(_) => {
                                tx.send(Ok((data_path, 0))).unwrap();  // TODO send file size
                            },
                            Err(error) => {
                                log::error!("Could not fetch file {:?}: {:?}", data_path, error);
                                tx.send(Err((data_path, format!("{}", error)))).unwrap();
                            }
                        };
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
            if let Ok((_, size)) = result {
                files_ok += 1;
                transfer_size += size;
            }
        }

        let errors = files_total - files_ok;
        if errors == 0 {
            log::info!("Cloning finished successfully: {} files total, {} from base backup, {} bytes transferred", files_total, files_from_base, transfer_size);
            fs::remove_file(self.path().join(".bdup.partial"))?;
            let status = Command::new("btrfs")
                .arg("property")
                .arg("set")
                .arg(self.path())
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

    fn create_volume(&self, base_backup: &Option<Backup>) -> Result<(), Box<dyn Error>> {
        if ! self.base_dir.exists() {
            fs::create_dir(&self.base_dir)?;
        }
        if let Some(base_backup) = base_backup {
            log::info!("Cloning previous backup {}", base_backup.display_name());
            let status = Command::new("btrfs")
                .arg("subvolume")
                .arg("snapshot")
                .arg(base_backup.path())
                .arg(self.path())
                .stdin(Stdio::null())
                .status()?;
            assert!(status.success());

            fs::read_dir(self.path())?
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
                .arg(self.path())
                .stdin(Stdio::null())
                .status()?;
            assert!(status.success());
            fs::create_dir(self.path().join("data"))?;
        }
        fs::File::create(self.path().join(".bdup.partial"))?;
        Ok(())
    }

    pub fn verify(&mut self) -> Result<u64, Box<dyn Error>> {
        let data_path = self.path().join("data");
        let mut files_in_manifest = HashSet::new();

        let manifest = fs::File::open(self.path().join("manifest.gz"))?;
        let gz = GzDecoder::new(manifest);
        let mut reader = io::BufReader::new(gz);

        let worker_pool = ThreadPool::new(2);
        let (tx, rx) = channel();

        let mut files_total = 0;
        manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
            if let Some(data) = &entry.data {
                files_total += 1;
                files_in_manifest.insert(data.path.to_owned());

                let checksum = data.md5.to_owned();
                let file_path = data_path.join(&data.path);
                let tx = tx.clone();
                worker_pool.execute(move || {
                    let result = match verify_file_md5(&file_path, &checksum) {
                        Ok((true, _)) => VerifyResult::Ok,
                        Ok((false, md5)) => VerifyResult::ChecksumMismatch(md5),
                        Err(err) => VerifyResult::Error(format!("Error computing checksum: {:?}", err))
                    };
                    tx.send(VerifyFileResult{ path: file_path, md5: checksum, result }).unwrap();
                });
            }
            Ok(())
        })?;
        drop(tx);

        let mut files_ok = 0;
        for result in rx.iter() {
            match result.result {
                VerifyResult::Ok => files_ok += 1,
                VerifyResult::ChecksumMismatch(computed) => {
                    log::error!("File's checksum did not match {:?}. Expected: {}, computed: {}", result.path, result.md5, computed);
                },
                VerifyResult::Error(err) => {
                    log::error!("Error while computing checksum for {:?}: {:?}", result.path, err);
                }
            };
        }

        visit_dirs(&data_path, &|entry: &fs::DirEntry| -> Result<(), Box<dyn Error>> {
            let path = entry.path().strip_prefix(&data_path)?.to_owned();
            if ! files_in_manifest.contains(&path) {
                log::info!("Found superfluous file while validating: {:?}", path);
            }
            Ok(())
        })?;

        log::info!("Verify finished: {}/{} files verified successfully", files_ok, files_total);
        Ok(files_total - files_ok)
    }
}

impl Ord for Backup {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for Backup {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Backup {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

fn verify_file_md5(file: &Path, md5: &str) -> io::Result<(bool, String)> {
    let input = fs::File::open(file)?;
    let digest = format!("{:x}", calc_md5(&mut GzDecoder::new(input))?);

    Ok((md5 == digest, digest))
}

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

