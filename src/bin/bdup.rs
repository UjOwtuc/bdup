use clap::Parser;
use serde_derive::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use threadpool::ThreadPool;

use burp::client::Client;
use burp::client::LocalClient;

#[cfg(feature = "http")]
use burp::remoteclient::RemoteClient;

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Config {
    log_level: log::LevelFilter,
    io_threads: usize,
    dest_dir: PathBuf,
    clients: Vec<ClientConfig>,
}

fn find_clients_at(base_dir: &Path) -> Result<Vec<ClientConfig>, Box<dyn Error>> {
    Ok(fs::read_dir(base_dir)?
        .filter_map(|result| result.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| ClientConfig {
            name: entry.file_name().to_string_lossy().to_string(),
            storage_url: entry.path().to_string_lossy().to_string(),
        })
        .collect())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: log::LevelFilter::Info,
            io_threads: 4,
            dest_dir: PathBuf::new(),
            clients: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ClientConfig {
    name: String,
    storage_url: String,
}

impl Eq for ClientConfig {}
impl PartialEq for ClientConfig {
    fn eq(&self, rhs: &Self) -> bool {
        self.name == rhs.name && self.storage_url == rhs.storage_url
    }
}

fn read_config(args: &Args) -> Result<Config, Box<dyn Error>> {
    let mut config = Config::default();
    if let Some(file) = &args.config_file {
        config = serde_yaml::from_reader(fs::File::open(file)?)?;
    }

    if let Some(level) = args.log_level {
        config.log_level = level;
    }
    if let Some(path) = &args.dest_dir {
        config.dest_dir = PathBuf::from(path);
    }
    if let Some(num) = args.iothreads {
        config.io_threads = num;
    }
    config.clients.extend(args.client.to_vec());
    for dir in &args.local_clients {
        config.clients.extend(find_clients_at(&PathBuf::from(dir))?);
    }

    Ok(config)
}

fn parse_client_arg(input: &str) -> Result<ClientConfig, String> {
    let mut split = input.splitn(2, '=');
    Ok(ClientConfig {
        name: split.next().unwrap().to_string(),
        storage_url: split.next().unwrap().to_string(),
    })
}

#[derive(Parser, Debug)]
struct Args {
    /// Set log level
    ///
    /// Possible values are: off, error, warn, info, debug, trace
    #[arg(short, long, value_enum, value_name = "LEVEL")]
    log_level: Option<log::LevelFilter>,

    /// Define client. Format: name=URL
    #[arg(short, long, value_parser = parse_client_arg)]
    client: Vec<ClientConfig>,

    /// Autodetect local clients in directory DIR
    #[arg(short = 'L', long, value_name = "DIR")]
    local_clients: Vec<String>,

    /// Destination directory
    #[arg(short, long, value_name = "DIR")]
    dest_dir: Option<String>,

    /// Read config from FILE
    #[arg(short = 'f', long, value_name = "FILE")]
    config_file: Option<String>,

    /// Dump config to stdout and exit
    #[arg(short = 'C', long)]
    dump_config: bool,

    /// Thread pool size for I/O operations (i.e. copying files)
    #[arg(short = 't', long)]
    iothreads: Option<usize>,
}

fn main() {
    let matches = Args::parse();
    let config = read_config(&matches).unwrap_or_else(|err| {
        panic!("Could not parse config: {:?}", err);
    });
    if matches.dump_config {
        println!(
            "{}",
            serde_yaml::to_string(&config)
                .unwrap_or_else(|err| panic!("Could not serialize config: {:?}", err))
        );
        return;
    }

    // TODO: sanity checks? e.g. dest_dir has to be a valid path

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(config.log_level)
        .chain(std::io::stdout())
        .apply()
        .unwrap_or_else(|err| panic!("Log init failed: {:?}", err));

    let mut clients: Vec<Box<dyn Client>> = Vec::new();
    for conf in config.clients {
        log::debug!("Loading list of existing backups for client {}", &conf.name);
        let mut client = create_client(&conf);
        client
            .find_backups(&conf.storage_url)
            .unwrap_or_else(|err| {
                log::error!(
                    "Could not find backups for client {}: {:?}",
                    &conf.name,
                    err
                )
            });
        clients.push(client);
    }

    clone_backups(&clients, &config.dest_dir, config.io_threads);
}

#[cfg(feature = "http")]
fn create_remote_client(conf: &ClientConfig) -> Box<dyn Client> {
    Box::new(RemoteClient::new(&conf.name))
}

#[cfg(not(feature = "http"))]
fn create_remote_client(conf: &ClientConfig) -> Box<dyn Client> {
    panic!("Unable to create remote client for URL {:?}, because bdup is compiled without \"http\" feature", conf.storage_url);
}

fn create_client(conf: &ClientConfig) -> Box<dyn Client> {
    if conf.storage_url.starts_with('/') || conf.storage_url.starts_with("file:/") {
        Box::new(LocalClient::new(&conf.name))
    } else {
        create_remote_client(conf)
    }
}

fn clone_backups(clients: &[Box<dyn Client>], dest: &Path, num_threads: usize) {
    if !dest.exists() {
        fs::create_dir(dest)
            .unwrap_or_else(|err| panic!("Could not create destination directory: {:?}", err));
    }

    let transfer_threads = ThreadPool::new(num_threads);
    for client in clients {
        if let Err(error) = client.clone_backups_to(&dest.join(client.name()), &transfer_threads) {
            log::error!("Error cloning backups of {}: {:?}", client.name(), error);
        }
    }
}
