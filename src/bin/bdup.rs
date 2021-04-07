use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use threadpool::ThreadPool;

use burp::client::Client;

fn get_directories(base_dir: &Path) -> io::Result<Vec<String>> {
    let mut dirs = Vec::new();
    for dir_entry in fs::read_dir(base_dir)? {
        let entry = dir_entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                dirs.push(name.to_owned());
            }
        }
    }

    Ok(dirs)
}

fn main() {
    let matches = clap::App::new("bdup")
        .version("0.1.0")
        .author("Karsten Borgwaldt <bdup@spambri.de>")
        .about("Duplicates burp backups")
        .arg(clap::Arg::with_name("source")
            .short("s")
            .long("source")
            .help("Source backup directory")
            .value_name("DIR")
            .default_value("/var/spool/burp")
            .takes_value(true))
        .arg(clap::Arg::with_name("log_level")
            .short("l")
            .long("log-level")
            .help("Set log level")
            .possible_values(&["trace", "debug", "info", "warn", "error"])
            .value_name("LEVEL")
            .default_value("info")
            .takes_value(true))
        .arg(clap::Arg::with_name("clients")
            .short("c")
            .long("clients")
            .help("Comma separated list of clients to work on")
            .value_name("CLIENTS")
            .multiple(true)
            .use_delimiter(true)
            .value_delimiter(",")
            .takes_value(true))
        .arg(clap::Arg::with_name("dest_dir")
            .short("d")
            .long("dest-dir")
            .help("Destination directory")
            .value_name("DIR")
            .takes_value(true)
            .required(true))
        .get_matches();

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!("{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::from_str(matches.value_of("log_level").unwrap()).expect("Unknwown log level"))
        .chain(std::io::stdout())
        .apply().unwrap_or_else(|err| panic!("Log init failed: {:?}", err));

    let source_dir = matches.value_of("source").unwrap();
    let client_names = if let Some(client_list) = matches.values_of("clients") {
        client_list.map(|s| s.to_owned()).collect()
    }
    else {
        log::debug!("Generating a list of clients from directories in source dir ({})", source_dir);
        get_directories(&PathBuf::from(&source_dir)).expect("Could not get client list")
    };

    log::debug!("source dir: {}", source_dir);
    log::debug!("clients: {}", client_names.join(", "));

    let mut clients = Vec::new();
    for name in client_names {
        log::debug!("Loading list of existing backups for client {}", name);
        let mut client = Client::new(&name);
        client.find_local_backups(&PathBuf::from(source_dir).join(&name)).unwrap_or_else(|err| log::error!("Could not find backups for client {}: {:?}", &name, err));
        clients.push(client);
    }

    let dest_dir = matches.value_of("dest_dir").unwrap();
    clone_backups(&clients, &PathBuf::from(dest_dir));
}

fn clone_backups(clients: &[Client], dest: &Path) {
    if ! dest.exists() {
        fs::create_dir(dest).unwrap_or_else(|err| panic!("Could not create destination directory: {:?}", err));
    }

    let transfer_threads = ThreadPool::new(2);
    for client in clients {
        if let Err(error) = client.clone_backups_to(&dest.join(&client.name), &transfer_threads) {
            log::error!("Error cloning backups of {}: {:?}", client.name, error);
        }
    }
}

