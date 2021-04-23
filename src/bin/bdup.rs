use serde_derive::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use threadpool::ThreadPool;

use burp::client::Client;

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

#[derive(Serialize, Deserialize, Debug)]
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

fn read_config(args: &clap::ArgMatches) -> Result<Config, Box<dyn Error>> {
    let mut config = Config::default();
    if let Some(file) = args.value_of("config_file") {
        config = serde_yaml::from_reader(fs::File::open(file)?)?;
    }

    if let Some(level) = args.value_of("log_level") {
        config.log_level = log::LevelFilter::from_str(level)?;
    }
    if let Some(path) = args.value_of("dest_dir") {
        config.dest_dir = PathBuf::from(path);
    }
    if let Some(num) = args.value_of("iothreads") {
        config.io_threads = num.parse::<usize>()?;
    }
    if let Some(clients) = args.values_of("client") {
        config.clients.extend(
            clients
                .map(|arg| -> ClientConfig {
                    let mut split = arg.splitn(2, '=');
                    ClientConfig {
                        name: split.next().unwrap().to_string(),
                        storage_url: split.next().unwrap().to_string(),
                    }
                })
                .collect::<Vec<ClientConfig>>(),
        );
    }
    if let Some(dirs) = args.values_of("local_clients") {
        for dir in dirs {
            config.clients.extend(find_clients_at(&PathBuf::from(dir))?);
        }
    }

    Ok(config)
}

fn init_args_parser() -> clap::App<'static, 'static> {
    clap::App::new("bdup")
        .version(clap::crate_version!())
        .author("Karsten Borgwaldt <bdup@spambri.de>")
        .about("Duplicates burp backups")
        .arg(
            clap::Arg::with_name("log_level")
                .short("l")
                .long("log-level")
                .help("Set log level")
                .possible_values(&["trace", "debug", "info", "warn", "error", "off"])
                .case_insensitive(true)
                .value_name("LEVEL")
                .default_value("info")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("client")
                .short("c")
                .long("client")
                .help("Define client. Format: name=URL")
                .value_name("CLIENT")
                .multiple(true)
                .number_of_values(1)
                .takes_value(true)
                .empty_values(false)
                .validator(|v: String| -> Result<(), String> {
                    if v.contains('=') {
                        Ok(())
                    } else {
                        Err("Format needs to be \"name=url\"".to_string())
                    }
                }),
        )
        .arg(
            clap::Arg::with_name("local_clients")
                .short("L")
                .long("local-clients")
                .help("Autodetect local clients in directory DIR")
                .value_name("DIR")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("dest_dir")
                .short("d")
                .long("dest-dir")
                .help("Destination directory")
                .value_name("DIR")
                .takes_value(true)
                .empty_values(false),
        )
        .arg(
            clap::Arg::with_name("config_file")
                .short("f")
                .long("config")
                .help("Read config from FILE")
                .value_name("FILE")
                .takes_value(true)
                .empty_values(false),
        )
        .arg(
            clap::Arg::with_name("dump_config")
                .short("C")
                .long("dump-config")
                .help("Dump config to stdout and exit"),
        )
        .arg(
            clap::Arg::with_name("iothreads")
                .short("t")
                .long("io-threads")
                .help("Thread pool size for I/O operations (i.e. copying files)")
                .value_name("NUM")
                .takes_value(true)
                .empty_values(false)
                .default_value("4")
                .validator(|v: String| -> Result<(), String> {
                    if let Ok(num) = v.parse::<usize>() {
                        if num > 0 {
                            return Ok(());
                        }
                    }
                    Err("Needs to an integer greater than zero".to_string())
                }),
        )
}

fn main() {
    let matches = init_args_parser().get_matches();
    let config = read_config(&matches).unwrap_or_else(|err| {
        panic!("Could not parse config: {:?}", err);
    });
    if matches.is_present("dump_config") {
        // println!("{}", toml::to_string_pretty(&config).unwrap_or_else(|err| panic!("Could not serialize config: {:?}", err)));
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

    let mut clients = Vec::new();
    for conf in config.clients {
        log::debug!("Loading list of existing backups for client {}", &conf.name);
        let mut client = Client::new(&conf.name);
        client
            .find_local_backups(&PathBuf::from(&conf.storage_url))
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

fn clone_backups(clients: &[Client], dest: &Path, num_threads: usize) {
    if !dest.exists() {
        fs::create_dir(dest)
            .unwrap_or_else(|err| panic!("Could not create destination directory: {:?}", err));
    }

    let transfer_threads = ThreadPool::new(num_threads);
    for client in clients {
        if let Err(error) = client.clone_backups_to(&dest.join(&client.name), &transfer_threads) {
            log::error!("Error cloning backups of {}: {:?}", client.name, error);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn arg_log_level_setting() {
        let res = init_args_parser().get_matches_from(vec!["bdup", "-l", "debug"]);
        assert_eq!(res.value_of("log_level"), Some("debug"));
    }

    #[test]
    fn arg_log_level_validator() {
        let res = init_args_parser().get_matches_from_safe(vec!["bdup", "-l", "something"]);
        assert!(res.is_err());
    }

    #[test]
    fn arg_client_multiple() {
        let res = init_args_parser().get_matches_from(vec!["bdup", "-c", "a=a,b,c", "-c", "b=b"]);
        let expexted: HashSet<&str> = ["a=a,b,c", "b=b"].iter().cloned().collect();
        let parsed: HashSet<_> = res.values_of("client").unwrap().collect();
        assert_eq!(expexted, parsed);
    }

    #[test]
    fn arg_client_validator() {
        let res = init_args_parser().get_matches_from_safe(vec!["bdup", "-c", "no_equals_sign"]);
        assert!(res.is_err());
    }

    #[test]
    fn arg_config_log_level() {
        let config =
            read_config(&init_args_parser().get_matches_from(vec!["bdup", "-l", "trace"])).unwrap();
        assert_eq!(config.log_level, log::LevelFilter::Trace);
    }

    #[test]
    fn arg_config_iothreads() {
        let config =
            read_config(&init_args_parser().get_matches_from(vec!["bdup", "-t", "99"])).unwrap();
        assert_eq!(config.io_threads, 99);
    }

    #[test]
    fn arg_config_dest_dir() {
        let config =
            read_config(&init_args_parser().get_matches_from(vec!["bdup", "-d", "/asdf"])).unwrap();
        assert_eq!(config.dest_dir, PathBuf::from("/asdf"));
    }

    #[test]
    fn config_clients_default_empty() {
        let config = read_config(&init_args_parser().get_matches_from(vec!["bdup"])).unwrap();
        assert!(config.clients.is_empty());
    }

    #[test]
    fn arg_config_clients() {
        let config = read_config(&init_args_parser().get_matches_from(vec![
            "bdup",
            "-c",
            "client_name=/some/comp=lex/path",
        ]))
        .unwrap();
        let expexted = ClientConfig {
            name: "client_name".to_string(),
            storage_url: "/some/comp=lex/path".to_string(),
        };
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0], expexted);
    }
}
