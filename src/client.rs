use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use threadpool::ThreadPool;

use crate::backup::Backup;
use crate::backup::TransferResult;

pub struct Client {
    pub name: String,
    backups: Vec<Backup>,
}

impl Client {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            backups: Vec::new(),
        }
    }

    pub fn find_local_backups(&mut self, base_dir: &Path) -> io::Result<()> {
        for dir_entry in fs::read_dir(base_dir)? {
            let entry = dir_entry?;
            match Backup::new(&entry.path()) {
                Ok(backup) => self.backups.push(backup),
                Err(error) => log::debug!(
                    "Skipping path {:?} because it is not a backup: {:?}",
                    &entry.path(),
                    error
                ),
            };
        }
        self.backups
            .sort_unstable_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
        Ok(())
    }

    pub fn clone_backups_to(
        &self,
        dest: &Path,
        transfer_threads: &ThreadPool,
    ) -> Result<(), Box<dyn Error>> {
        if !dest.exists() {
            fs::create_dir(dest)?;
        }

        let mut cloned = Client::new(&format!("cloned_{}", &self.name));
        cloned.find_local_backups(dest)?;

        for source in &self.backups {
            self.clone_backup(source, dest, &mut cloned, transfer_threads)?;
        }

        for backup in cloned
            .backups
            .iter_mut()
            .filter(|backup| !self.backups.contains(backup))
        {
            match backup.delete() {
                Ok(_) => log::debug!("Removed old backup {}", backup.path.display()),
                Err(error) => log::error!(
                    "Could not remove old backup {}: {:?}",
                    backup.path.display(),
                    error
                ),
            }
        }

        Ok(())
    }

    fn find_base_for(&mut self, id: u64) -> Option<&Backup> {
        let base = self
            .backups
            .iter_mut()
            .filter(|backup| backup.id < id)
            .max();

        if let Some(backup) = base {
            backup
                .load_checksums()
                .expect("Could not load checksums from base backup");
            Some(backup)
        } else {
            None
        }
    }

    fn clone_backup(
        &self,
        source: &Backup,
        dest: &Path,
        cloned: &mut Client,
        transfer_threads: &ThreadPool,
    ) -> Result<(), Box<dyn Error>> {
        let mut dest_backup = Backup::new(&dest.join(&source.dir_name()))?;

        if dest_backup.is_finished() {
            log::debug!("Backup {} is already finished.", dest_backup.path.display());
            return Ok(());
        }

        let base_backup = cloned.find_base_for(source.id);
        let base_msg = match base_backup {
            Some(backup) => format!("with base {}", backup.path.display()),
            None => "without base".to_string(),
        };
        log::info!(
            "Cloning backup {}/{} {}",
            &self.name,
            source.dir_name(),
            base_msg
        );
        dest_backup.clone_from(&base_backup, &|source_path, dest_path, tx| {
            let from = source.path.join(source_path);
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
        cloned.backups.push(dest_backup);
        Ok(())
    }
}
