use std::collections::{HashMap, HashSet};
use std::str;
use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::error::Error;
use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc::channel;
use flate2::read::GzDecoder;
use threadpool::ThreadPool;

use crate::manifest;
use crate::manifest::ManifestEntry;

pub fn find_backups(path: &Path) -> Result<Vec<Backup>, Box<dyn Error>>
{
    let mut backups = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().join("manifest.gz").exists() {
            let name = String::from_utf8(entry.path().as_os_str().as_bytes().to_vec())?;
            backups.push(Backup::from_path(path, &name)?);
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

pub struct Backup {
    pub base_dir: PathBuf,
    pub id: u32,
    timestamp: String,
    checksums: HashMap<PathBuf, String>
}

impl Backup {
    pub fn from_path(path: &Path, name: &str) -> Result<Self, Box<dyn Error>> {
        if path.join(name).join("manifest.gz").exists() {
            let id = name[0..7].parse::<u32>()?;
            Ok(Self{ base_dir: PathBuf::from(path), id, timestamp: name[8..].to_owned(), checksums: HashMap::new() })
        }
        else {
            Err(Box::new(manifest::ManifestReadError::new("no manifest.gz in given path")))
        }
    }

    pub fn display_name(&self) -> String {
        let client = format!("{:?}", self.base_dir.file_name().ok_or(""));
        format!("client={}, id={}, timestamp={}", client, self.id, self.timestamp)
    }

    pub fn path(&self) -> PathBuf {
        self.base_dir.join(format!("{:07} {}", self.id, self.timestamp))
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
                if let Some(md5) = &entry.md5 {
                    self.checksums.insert(PathBuf::from(&entry.path), md5.to_owned());
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    pub fn fetch_file(&self, entry: &ManifestEntry, src: &Backup, base: &Option<&Backup>) -> Result<(), Box<dyn Error>> {
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

    pub fn clone_from(&mut self, src: &Backup, base: &Option<&Backup>) -> Result<(), Box<dyn Error>> {
        if let Some(base_backup) = base {
            assert!(! base_backup.checksums.is_empty());
        }

        fs::copy(src.path().join("manifest.gz"), self.path().join("manifest.gz"))?;

        let manifest = fs::File::open(self.path().join("manifest.gz"))?;
        let gz = GzDecoder::new(manifest);
        let mut reader = io::BufReader::new(gz);
        manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
            if entry.data_path.is_some() {
                self.fetch_file(entry, src, base)?;
            }
            Ok(())
        })?;

        self.verify()?;
        fs::File::create(self.path().join(".bdup.finished"))?;
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

        manifest::read_manifest(&mut reader, &mut |entry: &ManifestEntry| {
            if let Some(checksum) = &entry.md5 {
                files_in_manifest.insert(PathBuf::from(entry.data_path.as_ref().unwrap()));

                let checksum = checksum.to_owned();
                let file_path = data_path.join(entry.data_path.as_ref().unwrap());
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

        let mut errors = 0;
        for result in rx.iter() {
            match result.result {
                VerifyResult::Ok => (),
                VerifyResult::ChecksumMismatch(computed) => {
                    log::error!("File's checksum did not match {:?}. Expected: {}, computed: {}", result.path, result.md5, computed);
                    errors += 1;
                },
                VerifyResult::Error(err) => {
                    log::error!("Error while computing checksum for {:?}: {:?}", result.path, err);
                    errors += 1;
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
        Ok(errors)
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

