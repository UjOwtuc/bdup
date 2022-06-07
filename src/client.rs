use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use threadpool::ThreadPool;

use crate::backup::Backup;
use crate::backup::TransferResult;

pub trait Client {
    fn find_backups(&mut self, url: &str) -> Result<(), Box<dyn Error>>;
    fn name(&self) -> &str;
    fn backups(&self) -> &HashMap<u64, Backup>;
    fn backups_mut(&mut self) -> &mut HashMap<u64, Backup>;

    fn read_file(&self, backup: u64, name: &str) -> Result<Box<dyn io::Read>, Box<dyn Error>>;

    fn clone_backups_to(
        &self,
        dest: &Path,
        transfer_threads: &ThreadPool,
    ) -> Result<(), Box<dyn Error>> {
        if !dest.exists() {
            fs::create_dir(dest)?;
        }

        let mut cloned = LocalClient::new(&format!("cloned_{}", self.name()));
        cloned.find_backups(&dest.to_string_lossy())?;

        for source in self.backups() {
            if source.1.is_finished() {
                self.clone_backup(source.1, dest, &mut cloned, transfer_threads)?;
            } else {
                log::info!(
                    "Skipping clone of {}, because it is not finished",
                    source.1.path().display()
                );
            }
        }

        for backup in cloned
            .backups
            .iter_mut()
            .filter(|backup| !self.backups().contains_key(backup.0))
        {
            match backup.1.delete() {
                Ok(_) => log::debug!("Removed old backup {}", backup.1.path().display()),
                Err(error) => log::error!(
                    "Could not remove old backup {}: {:?}",
                    backup.1.path().display(),
                    error
                ),
            }
        }

        Ok(())
    }

    fn find_base_for(&mut self, id: u64) -> Option<&Backup> {
        let base = self
            .backups_mut()
            .iter_mut()
            .filter(|backup| *backup.0 < id)
            .max();

        if let Some(backup) = base {
            backup
                .1
                .load_checksums()
                .expect("Could not load checksums from base backup");
            Some(backup.1)
        } else {
            None
        }
    }

    fn clone_backup(
        &self,
        source: &Backup,
        dest: &Path,
        cloned: &mut LocalClient,
        transfer_threads: &ThreadPool,
    ) -> Result<(), Box<dyn Error>> {
        let mut dest_backup = Backup::new(&dest.to_string_lossy(), &source.dir_name(), true)?;

        if dest_backup.is_finished() {
            log::debug!(
                "Backup {} is already finished.",
                dest_backup.path().display()
            );
            return Ok(());
        }

        let base_backup = cloned.find_base_for(source.id);
        let base_msg = match base_backup {
            Some(backup) => format!("with base {}", backup.path().display()),
            None => "without base".to_string(),
        };
        log::info!(
            "Cloning backup {}/{} {}",
            &self.name(),
            source.dir_name(),
            base_msg
        );
        dest_backup.clone_from(&base_backup, &|source_path, dest_path, tx| {
            let from = source.path().join(source_path);
            let to = dest_path.to_owned();
            let tx_clone = tx.clone();
            transfer_threads.execute(move || {
                if let Some(parent) = to.parent() {
                    fs::create_dir_all(parent).expect("Unable to create target directories");
                }
                let mut result = TransferResult {
                    source: from.to_owned().into(),
                    dest: to.to_owned().into(),
                    size: 0,
                    error: None,
                };
                match fs::copy(from, to) {
                    Ok(size) => result.size = size,
                    Err(error) => result.error = Some(format!("{:?}", error)),
                }
                tx_clone.send(result).expect("Unable to send result");
            });
        })?;
        cloned.backups.insert(dest_backup.id, dest_backup);
        Ok(())
    }
}

impl fmt::Debug for dyn Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Client({})", self.name())
    }
}

pub struct LocalClient {
    pub name: String,
    backups: HashMap<u64, Backup>,
}

impl LocalClient {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            backups: HashMap::new(),
        }
    }
}

impl Client for LocalClient {
    fn name(&self) -> &str {
        &self.name
    }

    fn backups(&self) -> &HashMap<u64, Backup> {
        &self.backups
    }

    fn backups_mut(&mut self) -> &mut HashMap<u64, Backup> {
        &mut self.backups
    }

    fn find_backups(&mut self, url: &str) -> Result<(), Box<dyn Error>> {
        let base_dir = PathBuf::from(url);
        for dir_entry in fs::read_dir(&base_dir)? {
            let entry = dir_entry?;
            match Backup::new(
                &base_dir.to_string_lossy(),
                &entry.file_name().to_string_lossy(),
                true,
            ) {
                Ok(backup) => {
                    self.backups.insert(backup.id, backup);
                }
                Err(error) => log::debug!(
                    "Skipping path {:?} because it is not a backup: {:?}",
                    &entry.path(),
                    error
                ),
            };
        }
        // self.backups
        //     .sort_unstable_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
        Ok(())
    }

    fn read_file(&self, backup: u64, name: &str) -> Result<Box<dyn io::Read>, Box<dyn Error>> {
        let base_path = self.backups.get(&backup).unwrap().path();
        Ok(Box::new(fs::File::open(base_path.join(name))?))
    }
}
