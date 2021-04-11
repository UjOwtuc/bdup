use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::io;
use std::fs;
use std::fmt;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::ffi::{OsStr, OsString};
use std::error::Error;
use std::process::{Command, Stdio};
use std::cmp::Ordering;
use flate2::read::GzDecoder;
use threadpool::ThreadPool;

use crate::manifest;

enum VerifyResult {
    Ok,
    FilesizeMismatch(usize),
    ChecksumMismatch(String),
    Error(String),
}

struct VerifyFileResult {
    path: PathBuf,
    size: usize,
    md5: String,
    result: VerifyResult
}

fn format_bytes(bytes: u64) -> String {
    let prefix = ["", "ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"];
    let mut index = 0;
    let mut num: f64 = bytes as f64;
    while num > 1000.0 {
        num /= 1024.0;
        index += 1;
    }
    format!("{:.2} {}B", num, prefix[index])
}

pub struct TransferResult {
    pub source: OsString,
    pub dest: OsString,
    pub size: u64,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct Backup {
    pub path: PathBuf,
    pub id: u64,
    timestamp: String,
    checksums: HashMap<PathBuf, String>,
}

#[derive(Debug)]
struct InvalidNameError {
    message: String
}

impl fmt::Display for InvalidNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl Error for InvalidNameError {}

impl Backup {
    pub fn new(path: &Path) -> Result<Self, Box<dyn Error>> {
        let dir = path.file_name().expect("Invalid path for local backup: no file_name component").to_string_lossy();
        let (id, timestamp) = Self::parse_name(&dir)?;
        Ok(Self {
            path: path.to_owned(),
            id,
            timestamp,
            checksums: HashMap::new(),
        })
    }

    fn parse_name(name: &str) -> Result<(u64, String), Box<dyn Error>> {
        if name.len() < 8 {
            Err(Box::new(InvalidNameError{ message: "Name too short".to_string() }))
        }
        else {
            let id = name[0..7].parse::<u64>()?;
            Ok((id, name[8..].to_owned()))
        }
    }

    pub fn delete(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Removing backup at {}", self.path.display());
        let status = Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(self.path.to_owned())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()?;
        assert!(status.success());
        self.checksums = HashMap::new();
        Ok(())
    }

    #[inline]
    fn metadata_files() -> &'static [&'static str] where Self: Sized {
        &["manifest.gz", "log.gz", "backup_stats", "timestamp", "incexc"]
    }

    fn manifest_reader(&self) -> Result<io::BufReader<flate2::read::GzDecoder<fs::File>>, Box<dyn Error>> {
        let manifest = fs::File::open(self.file_path(None, &OsString::from("manifest.gz")))?;
        let gz = GzDecoder::new(manifest);
        Ok(io::BufReader::new(gz))
    }

    fn file_path(&self, prefix: Option<&str>, path: &OsStr) -> PathBuf {
        let mut real_path = PathBuf::from(&self.path);
        if let Some(prefix) = prefix {
            real_path = real_path.join(prefix);
        }
        real_path.join(path)
    }

    fn create_volume(&self, base_backup: &Option<&Backup>) -> Result<(), Box<dyn Error>> {
        if let Some(parent_dir) = self.path.parent() {
            if ! parent_dir.exists() {
                fs::create_dir(parent_dir)?;
            }
        }

        if let Some(base_backup) = base_backup {
            log::debug!("Cloning previous backup {:?}", base_backup.path);
            let status = Command::new("btrfs")
                .arg("subvolume")
                .arg("snapshot")
                .arg(base_backup.path.to_owned())
                .arg(self.path.to_owned())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
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
                .stdout(Stdio::null())
                .status()?;
            assert!(status.success());
            fs::create_dir(self.path.join("data"))?;
        }
        fs::File::create(self.path.join(".bdup.partial"))?;
        Ok(())
    }

    fn wait_for_transfer(&self, rx: &Receiver<TransferResult>, return_after: Option<&OsStr>) -> (u64, u64) {
        let mut files_ok = 0;
        let mut transfer_size = 0;
        for result in rx.iter() {
            match result.error {
                None => {
                    files_ok += 1;
                    transfer_size += result.size;
                },
                Some(error) => log::error!("Could not fetch file {:?}: {:?}", result.source, error),
            }
            if let Some(path) = return_after {
                if path == result.dest {
                    break;
                }
            }
        }

        (files_ok, transfer_size)
    }

    pub fn clone_from(&mut self, base_backup: &Option<&Backup>, fetch_callback: &dyn Fn(&OsStr, &Path, &Sender<TransferResult>)) -> Result<(), Box<dyn Error>> {
        if self.is_finished() {
            log::info!("Cloning to {:?} already finished. Skipping", self.path);
            return Ok(());
        }

        if let Some(backup) = base_backup {
            assert!(! backup.get_checksums().is_empty());
        }
        self.create_volume(base_backup)?;

        let (tx, rx) = channel();

        let mut files_total = 0;
        let mut files_from_base = 0;

        log::debug!("Fetching metadata");
        for filename in Self::metadata_files() {
            files_total += 1;
            let dest_path = self.path.join(filename);
            fetch_callback(OsStr::new(filename), &dest_path, &tx.clone());
        }
        let (mut files_ok, mut transfer_size) = self.wait_for_transfer(&rx, Some(self.path.join("manifest.gz").as_os_str()));

        log::debug!("Starting data transfers");
        let mut files_in_manifest = HashSet::new();
        manifest::read_manifest(&mut self.manifest_reader()?, &mut |entry: &manifest::ManifestEntry| {
            if let Some(data) = &entry.data {
                self.checksums.insert(data.path.to_owned(), data.md5.to_owned());
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
                    fetch_callback(&PathBuf::from("data").join(data_path).into_os_string(), &dest_path, &tx.clone());
                }
            }
            Ok(())
        })?;
        drop(tx);

        log::debug!("Waiting for queued transfers to finish");
        let (num, size) = self.wait_for_transfer(&rx, None);
        files_ok += num;
        transfer_size += size;

        if base_backup.is_some() {
            log::debug!("Removing superfluous files (cloned from base, not in this backup)");
            let unwanted = self.unwanted_files()?;
            log::debug!("Found {} unwanted files", unwanted.len());
            unwanted.iter().map(|path| -> Result<(), Box<dyn Error>> {
                fs::remove_file(path)?;
                for parent in path.parent().unwrap().ancestors() {
                    if parent.read_dir()?.next().is_none() {
                        fs::remove_dir(parent)?;
                    }
                }
                Ok(())
            })
                .filter_map(|result| result.err())
                .for_each(|err| log::warn!("Could not remove file: {:?}", err));
        }

        let errors = files_total - files_ok - files_from_base;
        if errors == 0 {
            log::info!("Cloning finished successfully: {} files total, {} from base backup, {} transferred", files_total, files_from_base, format_bytes(transfer_size));
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
            log::warn!("Cloning finished with errors: {}/{} files were successful, {} from base backup, {} transferred", files_from_base + files_ok, files_total, files_from_base, format_bytes(transfer_size));
        }
        Ok(())
    }

    fn unwanted_files(&self) -> Result<Vec<PathBuf>, Box<dyn Error>> {
        // TODO: return descriptive error instead
        assert!(! self.checksums.is_empty());

        let data_path = self.path.join("data");
        let iter = fs::read_dir(&data_path)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                if let Ok(path) = entry.path().strip_prefix(&data_path) {
                    return ! self.checksums.contains_key(path)
                }
                false
            })
            .map(|entry| entry.path());
        Ok(iter.collect())
    }

    pub fn dir_name(&self) -> String {
        format!("{:07} {}", self.id, self.timestamp)
    }

    pub fn load_checksums(&mut self) -> Result<(), Box<dyn Error>> {
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

    pub fn is_finished(&self) -> bool {
        self.path.join("manifest.gz").exists() && ! self.path.join(".bdup.partial").exists()
    }

    fn get_checksums(&self) -> &HashMap<PathBuf, String> {
        if self.checksums.is_empty() {
            log::debug!("getting empty checksum map from backup {}", self.path.display());
        }
        &self.checksums
    }

    pub fn verify(&mut self, worker_threads: usize) -> Result<u64, Box<dyn Error>> {
        let data_path = self.path.join("data");
        let mut files_in_manifest = HashSet::new();

        let manifest = fs::File::open(self.path.join("manifest.gz"))?;
        let gz = GzDecoder::new(manifest);
        let mut reader = io::BufReader::new(gz);

        let worker_pool = ThreadPool::new(worker_threads);
        let (tx, rx) = channel();

        let mut files_total = 0;
        manifest::read_manifest(&mut reader, &mut |entry: &manifest::ManifestEntry| {
            if let Some(data) = &entry.data {
                files_total += 1;
                files_in_manifest.insert(data.path.to_owned());

                let size = data.size;
                let checksum = data.md5.to_owned();
                let file_path = data_path.join(&data.path);
                let tx = tx.clone();
                worker_pool.execute(move || {
                    let result = match verify_file_md5(&file_path, size, &checksum) {
                        Ok((true, _, _)) => VerifyResult::Ok,
                        Ok((false, read_size, md5)) =>  {
                            if read_size != size {
                                VerifyResult::FilesizeMismatch(read_size)
                            }
                            else {
                                VerifyResult::ChecksumMismatch(md5)
                            }
                        },
                        Err(err) => VerifyResult::Error(format!("Error computing checksum: {:?}", err))
                    };
                    tx.send(VerifyFileResult{ path: file_path, size, md5: checksum, result }).unwrap();
                });
            }
            Ok(())
        })?;
        drop(tx);

        let mut files_ok = 0;
        for result in rx.iter() {
            match result.result {
                VerifyResult::Ok => files_ok += 1,
                VerifyResult::FilesizeMismatch(size) => {
                    log::error!("File does not have correct size {:?}. Expected: {}, real: {}", result.path, result.size, size);
                },
                VerifyResult::ChecksumMismatch(computed) => {
                    log::error!("File's checksum did not match {:?}. Expected: {}, computed: {}", result.path, result.md5, computed);
                },
                VerifyResult::Error(err) => {
                    log::error!("Error while computing checksum for {:?}: {:?}", result.path, err);
                }
            };
        }

        let unwanted = self.unwanted_files()?;
        if ! unwanted.is_empty() {
            log::info!("Found {} superfluous files while validating: {:?}", unwanted.len(), unwanted);
        }

        log::info!("Verify finished: {}/{} files verified successfully", files_ok, files_total);
        Ok(files_total - files_ok)
    }
}

impl Eq for Backup {}

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
        self.id == other.id && self.timestamp == other.timestamp
    }
}

fn verify_file_md5(file: &Path, size: usize, md5: &str) -> io::Result<(bool, usize, String)> {
    let input = fs::File::open(file)?;
    let (read_size, digest) = calc_md5(&mut GzDecoder::new(input))?;
    let digest = format!("{:x}", digest);

    Ok((read_size == size && md5 == digest, size, digest))
}

fn calc_md5<T: io::Read>(reader: &mut T) -> io::Result<(usize, md5::Digest)> {
    let mut ctx = md5::Context::new();
    let mut buf = vec![0_u8; 4096];
    let mut size = 0;
    loop {
        let len = reader.read(&mut buf)?;
        ctx.consume(&buf[0..len]);
        size += len;
        if len == 0 {
            break;
        }
    }
    Ok((size, ctx.compute()))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use std::thread;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1), "1.00 B");
        assert_eq!(format_bytes(234), "234.00 B");
        assert_eq!(format_bytes(1024), "1.00 kiB");
        assert_eq!(format_bytes(456 * 1024), "456.00 kiB");
        assert_eq!(format_bytes((2.5 * 1024.0) as u64), "2.50 kiB");
        assert_eq!(format_bytes((99.0001 * 1024.0 * 1024.0) as u64), "99.00 MiB");
    }

    #[test]
    fn parse_name() {
        assert_eq!(Backup::parse_name("0000015 2019-04-13 18:02:26").unwrap(), (15, "2019-04-13 18:02:26".to_string()));
    }

    #[test]
    fn parse_name_too_short() {
        let result = Backup::parse_name("123");
        assert!(result.is_err());
    }

    #[test]
    fn backup_new() {
        let backup = Backup::new(&PathBuf::from("/some/distant/path/0000001 2021-04-11 00:00:00")).unwrap();
        assert_eq!(backup.id, 1);
        assert_eq!(backup.timestamp, "2021-04-11 00:00:00");
    }

    #[test]
    fn calc_md5_lorem() {
        let lorem = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua";
        let (size, digest) = calc_md5(&mut Cursor::new(lorem)).unwrap();
        assert_eq!(size, lorem.len());
        assert_eq!(format!("{:x}", digest), "112e6e5d321385d524234210bdebec02")
    }

    #[test]
    fn metadata_contains_manifest() {
        assert!(Backup::metadata_files().contains(&"manifest.gz"));
    }

    #[test]
    fn file_path() {
        let backup = Backup::new(&PathBuf::from("/0000001 2021-04-11 00:00:00")).unwrap();
        assert_eq!(
            backup.file_path(None, &OsString::from("filename")),
            PathBuf::from("/0000001 2021-04-11 00:00:00/filename"));
        assert_eq!(
            backup.file_path(Some("prefix"), &OsString::from("filename")),
            PathBuf::from("/0000001 2021-04-11 00:00:00/prefix/filename"));
    }

    fn send_file_results(tx: Sender<TransferResult>, error: Option<String>) {
        tx.send(TransferResult{
            source: OsString::from("source path"),
            dest: OsString::from("first dest path"),
            size: 123,
            error: error.clone(),
        }).unwrap_or_else(|err| panic!("send failed: {:?}", err));
        tx.send(TransferResult{
            source: OsString::from("source path"),
            dest: OsString::from("second dest path"),
            size: 123,
            error: error.clone(),
        }).unwrap_or_else(|err| panic!("send failed: {:?}", err));
        tx.send(TransferResult{
            source: OsString::from("source path"),
            dest: OsString::from("third dest path"),
            size: 123,
            error: error,
        }).unwrap_or_else(|err| panic!("send failed: {:?}", err));
    }

    #[test]
    fn wait_for_named_transfer() {
        let backup = Backup::new(&PathBuf::from("/0000001 2021-04-11 00:00:00")).unwrap();
        let (tx, rx) = channel();
        let sender = thread::spawn(move || send_file_results(tx, None));
        let (num, size) = backup.wait_for_transfer(&rx, Some(&OsString::from("second dest path")));
        assert_eq!(num, 2);
        assert_eq!(size, 246);
        sender.join().unwrap_or_else(|err| panic!("join failed: {:?}", err));
    }

    #[test]
    fn wait_for_all_transfer() {
        let backup = Backup::new(&PathBuf::from("/0000001 2021-04-11 00:00:00")).unwrap();
        let (tx, rx) = channel();
        let sender = thread::spawn(move || send_file_results(tx, None));
        let (num, size) = backup.wait_for_transfer(&rx, None);
        assert_eq!(num, 3);
        assert_eq!(size, 369);
        sender.join().unwrap_or_else(|err| panic!("join failed: {:?}", err));
    }

    #[test]
    fn wait_for_transfer_errors() {
        let backup = Backup::new(&PathBuf::from("/0000001 2021-04-11 00:00:00")).unwrap();
        let (tx, rx) = channel();
        let sender = thread::spawn(move || send_file_results(tx, Some("test error".to_string())));
        let (num, _size_ignored) = backup.wait_for_transfer(&rx, None);
        assert_eq!(num, 0);
        sender.join().unwrap_or_else(|err| panic!("join failed: {:?}", err));
    }

    #[test]
    fn dir_name() {
        assert_eq!(
            Backup::new(&PathBuf::from("/0000001 2021-04-11 00:00:00")).unwrap().dir_name(),
            "0000001 2021-04-11 00:00:00");
        assert_eq!(
            Backup::new(&PathBuf::from("/9876543 asd asd ! | äöüß")).unwrap().dir_name(),
            "9876543 asd asd ! | äöüß");
        assert_eq!(
            Backup::new(&PathBuf::from("/ignore/any/path/before/backup/9999999 x")).unwrap().dir_name(),
            "9999999 x");
    }

    #[test]
    fn get_checksums() {
        // getting an empty checksum map does not make sense but is not an error
        assert!(Backup::new(&PathBuf::from("/0000001 2021-04-11 00:00:00")).unwrap().get_checksums().is_empty());
    }

    #[test]
    fn backup_equal() {
        assert_eq!(Backup::new(&PathBuf::from("/0000001 some timestamp")).unwrap(),
            Backup::new(&PathBuf::from("/0000001 some timestamp")).unwrap());

        // different timestamp
        assert_ne!(Backup::new(&PathBuf::from("/0000001 some timestamp")).unwrap(),
            Backup::new(&PathBuf::from("/0000001 other timestamp")).unwrap());

        // different id
        assert_ne!(Backup::new(&PathBuf::from("/0000001 some timestamp")).unwrap(),
            Backup::new(&PathBuf::from("/0000002 some timestamp")).unwrap());
    }
}

