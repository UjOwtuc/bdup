use serde_derive::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::io;

use crate::backup::Backup;
use crate::client::Client;

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[derive(Deserialize)]
struct FileListItem {
    pub name: String,
    #[serde(rename = "type")]
    pub filetype: String,
    // pub mtime: String,
    // pub size: Option<usize>,
}

pub struct RemoteClient {
    pub name: String,
    backups: HashMap<u64, Backup>,
    http_client: reqwest::blocking::Client,
}

impl RemoteClient {
    pub fn new(name: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()
            .unwrap();
        Self {
            name: name.to_owned(),
            backups: HashMap::new(),
            http_client: client,
        }
    }
}

impl Client for RemoteClient {
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
        log::debug!("Fetching backup list from {:?}", url);

        let filelist = self
            .http_client
            .get(url)
            .send()?
            .json::<Vec<FileListItem>>()?;
        for item in filelist.iter().filter(|item| item.filetype == "directory") {
            match Backup::new(url, &item.name, false) {
                Ok(backup) => {
                    self.backups.insert(backup.id, backup);
                }
                Err(error) => log::debug!(
                    "Skipping directory {:?} because it is not a backup: {:?}",
                    item.name,
                    error
                ),
            };
        }
        // self.backups
        //     .sort_unstable_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
        Ok(())
    }

    fn read_file(&self, backup: u64, name: &str) -> Result<Box<dyn io::Read>, Box<dyn Error>> {
        let url = format!(
            "{}/{}",
            self.backups.get(&backup).unwrap().path().to_string_lossy(),
            name
        );
        Ok(Box::new(io::Cursor::new(
            self.http_client.get(url).send()?.text()?,
        )))
    }
}
