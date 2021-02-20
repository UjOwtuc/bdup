use std::convert::{TryFrom, TryInto};
use std::{fmt, str};
use std::error::Error;
use std::io::BufRead;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use chrono::NaiveDateTime;


#[derive(Debug)]
pub struct ManifestReadError {
    details: String
}

impl ManifestReadError {
    pub fn new(msg: &str) -> ManifestReadError {
        ManifestReadError{ details: msg.to_string() }
    }
}

impl fmt::Display for ManifestReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for ManifestReadError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Default)]
pub struct Mode {
    mode: u32
}

fn format_mode_part(part: u32, dest: &mut String) {
    dest.push_str(match part & 4 {
        0 => "-",
        _ => "r"
    });
    dest.push_str(match part & 2 {
        0 => "-",
        _ => "w"
    });
    dest.push_str(match part & 1 {
        0 => "-",
        _ => "x"
    });
}

impl From<&Mode> for String {
    fn from(mode: &Mode) -> String {
        let mut readable = String::new();
        format_mode_part((mode.mode & 0o700) >> 6, &mut readable);
        format_mode_part((mode.mode & 0o70) >> 3, &mut readable);
        format_mode_part(mode.mode, &mut readable);
        if mode.mode & 0o4000 == 0o4000 {
            readable.replace_range(2..3, "s");
        }
        return readable;
    }
}

impl From<i64> for Mode {
    fn from(value: i64) -> Self {
        Mode { mode: u32::try_from(value & 0xFFFFFFFF).unwrap() }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

#[derive(PartialEq, Debug)]
pub enum FileType {
    Unknown,
    Plain,
    Directory,
    SoftLink,
    HardLink,
}

#[derive(Default)]
pub struct Stat {
    pub containing_device: u64,
    pub inode: u64,
    pub mode: Mode,
    pub num_links: u64,
    pub owner_id: u64,
    pub group_id: u64,
    pub device_id: u64,
    pub size: u64,
    pub blocksize: u64,
    pub blocks: u64,
    pub access_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub ch_flags: u64,
    win_attr: String,  // don't know, what this might be

    pub compression: i32,
    // encryption: i32,
    // salt: String
}

fn burp_decode_base64(value: &str) -> i64 {
    let mut result: i64 = 0;
    let mut negative = false;

    let mut val = value;
    // i don't care about leading spaces. do i need to?
    if value.chars().nth(0).unwrap() == '-' {
        negative = true;
        val = &value[1..];
    }

    for c in val.chars() {
        result <<= 6;
        match c {
            'A' ..= 'Z' => result += (c as u8 - 'A' as u8) as i64,
            'a' ..= 'z' => result += (c as u8 - 'a' as u8) as i64 + 26,
            '0' ..= '9' => result += (c as u8 - '0' as u8) as i64 + 32,
            '+' => result += 62,
            '/' => result += 63,
            _ => panic!()
        }
    }

    if negative {
        result *= -1;
    }
    return result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        assert_eq!(burp_decode_base64("Po"), 1000);
    }

    #[test]
    fn format_part() {
        let mut val = String::new();
        format_mode_part(0o7, &mut val);
        assert_eq!(val, "rwx");

        val.clear();
        format_mode_part(0o6, &mut val);
        assert_eq!(val, "rw-");

        val.clear();
        format_mode_part(0o1, &mut val);
        assert_eq!(val, "--x");
    }

    #[test]
    fn format_mode() {
        let mode = Mode{ mode: 0o147 };
        assert_eq!(String::from(&mode), "--xr--rwx");
    }
}

impl TryFrom<&[u8]> for Stat {
    type Error = ManifestReadError;

    fn try_from(line: &[u8]) -> Result<Self, Self::Error> {
        let source = str::from_utf8(line).map_err(|err| ManifestReadError::new(&format!("Non utf8 chars in stat line: {:?}", err)))?;
        let stat = source.split(" ").collect::<Vec<&str>>();
        if stat.len() < 16 {
            return Err(ManifestReadError::new(&format!("Too few entries in stat line. Expected 16, found {}", stat.len())));
        }

        let mut result = Self{ ..Default::default() };
        result.containing_device = burp_decode_base64(stat[0]).try_into().map_err(|err| ManifestReadError::new(&format!("corrupt containing_device: {:?}", err)))?;
        result.inode = burp_decode_base64(stat[1]).try_into().map_err(|err| ManifestReadError::new(&format!("corrupt inode: {:?}", err)))?;
        result.mode = burp_decode_base64(stat[2]).try_into().unwrap();
        result.num_links = burp_decode_base64(stat[3]).try_into().unwrap();
        result.owner_id = burp_decode_base64(stat[4]).try_into().unwrap();
        result.group_id = burp_decode_base64(stat[5]).try_into().unwrap();
        result.device_id = burp_decode_base64(stat[6]).try_into().unwrap();
        result.size = burp_decode_base64(stat[7]).try_into().unwrap();
        result.blocksize = burp_decode_base64(stat[8]).try_into().unwrap();
        result.blocks = burp_decode_base64(stat[9]).try_into().unwrap();
        result.access_time = burp_decode_base64(stat[10]).try_into().unwrap();
        result.mod_time = burp_decode_base64(stat[11]).try_into().unwrap();
        result.change_time = burp_decode_base64(stat[12]).try_into().unwrap();
        result.ch_flags = burp_decode_base64(stat[13]).try_into().unwrap();
        result.win_attr = stat[14].to_owned();
        result.compression = burp_decode_base64(stat[15]).try_into().unwrap();
        // result.encryption = burp_decode_base64(stat[16]).try_into().unwrap();
        // result.salt = stat[17].to_owned();

        return Ok(result);
    }
}

pub struct ManifestEntry {
    file_type: FileType,
    pub path: PathBuf,
    pub stat: Stat,
    pub data_path: Option<PathBuf>,
    size: Option<u64>,
    pub md5: Option<String>,
    link_target: Option<PathBuf>,
}

impl ManifestEntry {
    fn new() -> Self {
        Self{
            file_type: FileType::Unknown,
            path: PathBuf::new(),
            stat: Stat::default(),
            data_path: None,
            size: None,
            md5: None,
            link_target: None,
        }
    }
}


impl fmt::Display for ManifestEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match &self.file_type {
            FileType::Directory => 'd',
            FileType::SoftLink => 'l',
            _ => '-',
        })?;

        let owner = format!("{}", self.stat.owner_id);
        let group = format!("{}", self.stat.group_id);
        let tstamp = NaiveDateTime::from_timestamp(self.stat.mod_time.try_into().unwrap(), 0);

        let size = match self.size {
            Some(bytes) => bytes,
            None => 0
        };

        write!(f, "{} {:10} {:10} {:8} {} {:?}", self.stat.mode, owner, group, size, tstamp, &self.path)?;
        if self.file_type == FileType::SoftLink {
            if let Some(target) = &self.link_target {
                write!(f, " -> {:?}", &target)?;
            }
            else {
                write!(f, " -> (unknown target)")?;
            }
        }
        Ok(())
    }
}

fn add_manifest_line(entry: &mut ManifestEntry, kind: &u8, data: &[u8]) -> Result<bool, Box<dyn Error>> {
    let mut finished = false;

    match kind {
        b'r' => entry.stat = Stat::try_from(&data[..])?,
        b'f' => {
            entry.file_type = FileType::Plain;
            entry.path = PathBuf::from(OsStr::from_bytes(data));
        },
        b'd' => {
            entry.file_type = FileType::Directory;
            entry.path = PathBuf::from(OsStr::from_bytes(data));
            finished = true;
        },
        b'l' => {
            if entry.file_type == FileType::SoftLink {
                entry.link_target = Some(PathBuf::from(OsStr::from_bytes(data)));
                finished = true;
            }
            else {
                entry.file_type = FileType::SoftLink;
                entry.path = PathBuf::from(OsStr::from_bytes(data));
            }
        },
        b'L' => entry.file_type = FileType::HardLink,
        b't' => entry.data_path = Some(PathBuf::from(OsStr::from_bytes(data))),
        b'x' => {
            let info = str::from_utf8(data).unwrap();
            let val = info.split(":").collect::<Vec<&str>>();
            entry.size = Some(val[0].parse::<u64>().unwrap());
            entry.md5 = Some(val[1].to_owned());
            finished = true;
        },
        _ => log::debug!("Ignoring line starting with '{}'", *kind as char)
    };

    Ok(finished)
}

pub fn read_manifest<R: BufRead, T, F: FnMut(&ManifestEntry) -> Result<T, Box<dyn Error>>>(reader: &mut R, callback: &mut F) -> Result<(), Box<dyn Error>> {
    let mut entry = ManifestEntry::new();
    let mut line = Vec::new();

    let mut lineno = 0;
    loop {
        lineno += 1;
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(n @ 1 ..= 3) => {
                log::debug!("Short read in line {}, buffer: {:?}", lineno, line);
                return Err(Box::new(ManifestReadError::new(&format!("Short read of {} bytes", n))));
            },
            Ok(_) => (),
            Err(e) => return Err(Box::new(e)),
        };

        while (line[line.len() -1] as char).is_whitespace() {
            line.pop();
        }
        let data = &line[5..];

        match add_manifest_line(&mut entry, &line[0], data) {
            Ok(false) => (),
            Ok(true) => {
                callback(&entry)?;
                entry = ManifestEntry::new();
            },
            Err(err) => {
                log::debug!("Error in line {}: {:?}", lineno, err);
                return Err(Box::new(ManifestReadError::new(&format!("{}: Corrupt line in manifest: {:?}", lineno, err))));
            }
        }
        line.clear();
    }
    Ok(())
}

