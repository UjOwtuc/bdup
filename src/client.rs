use std::path::Path;
use std::io;
use std::fs;
use std::error::Error;
use std::sync::Arc;

use crate::backup::BurpBackup;
use crate::backup::LocalBurpBackup;


pub struct BurpClient {
    pub name: String,
    backups: Vec<Arc<dyn BurpBackup + Sync + Send>>,
}

impl BurpClient {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            backups: Vec::new()
        }
    }

    pub fn find_local_backups(&mut self, base_dir: &Path) -> io::Result<()> {
        for dir_entry in fs::read_dir(base_dir)? {
            let entry = dir_entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.backups.push(Arc::new(LocalBurpBackup::new(&entry.path())));
            }
        }
        self.backups.sort_unstable_by(|a, b| {a.id().partial_cmp(&b.id()).unwrap()});
        Ok(())
    }

    /*
    pub fn find_remote_backups(&mut self, base_url: &str) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
    */

    pub fn clone_backups_to(&self, dest: &Path) -> Result<(), Box<dyn Error>> {
        if ! dest.exists() {
            // TODO: create a subvolume for each client?
            fs::create_dir(dest)?;
        }

        let mut cloned = BurpClient::new(&format!("cloned_{}", &self.name));
        cloned.find_local_backups(dest)?;

        for source in &self.backups {
            self.clone_backup(source, dest, &mut cloned)?;
        }

        Ok(())
    }

    fn clone_backup(&self, source: &Arc<dyn BurpBackup + Sync + Send>, dest: &Path, cloned: &mut BurpClient) -> Result<(), Box<dyn Error>> {
        let mut dest_backup = LocalBurpBackup::new(&dest.join(source.dir_name()));

        if dest_backup.is_finished() {
            log::info!("Backup {}/{} is already finished.", &self.name, source.dir_name());
            return Ok(())
        }

        let base_backup = cloned.backups.iter()
            .filter(|backup| backup.id() < source.id())
            .filter(|backup| backup.is_local())
            .max();
        log::info!("Cloning backup {}/{} with base {}", &self.name, source.dir_name(), match base_backup {
            Some(base) => base.dir_name(),
            None => "None".to_string()
        });
        dest_backup.clone_from(&base_backup, source)?;
        cloned.backups.push(Arc::new(dest_backup));
        Ok(())
    }
}

