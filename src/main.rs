use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str;
use std::fs::File;
use std::io::{BufReader, BufRead};
use flate2::read::GzDecoder;
use chrono::NaiveDateTime;

#[derive(Default)]
struct Mode {
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
enum FileType {
    Unknown,
    Plain,
    Directory,
    SoftLink,
    HardLink,
}

#[derive(Default)]
struct Stat {
    containing_device: u64,
    inode: u64,
    mode: Mode,
    num_links: u64,
    owner_id: u64,
    group_id: u64,
    device_id: u64,
    size: u64,
    blocksize: u64,
    blocks: u64,
    access_time: u64,
    mod_time: u64,
    change_time: u64,
    ch_flags: u64,
    win_attr: String,  // don't know, what this might be

    compression: i32,
    encryption: i32,
    salt: String
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
    type Error = &'static str;

    fn try_from(line: &[u8]) -> Result<Self, Self::Error> {
        let source = str::from_utf8(line).unwrap();
        let stat = source.split(" ").collect::<Vec<&str>>();
        let mut result = Self{ ..Default::default() };
        result.containing_device = burp_decode_base64(stat[0]).try_into().unwrap();
        result.inode = burp_decode_base64(stat[1]).try_into().unwrap();
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
        result.encryption = burp_decode_base64(stat[16]).try_into().unwrap();
        result.salt = stat[17].to_owned();

        return Ok(result);
    }
}

struct ManifestEntry {
    file_type: FileType,
    path: Vec<u8>,
    stat: Stat,
    data_path: Option<Vec<u8>>,
    size: Option<u64>,
    md5: Option<String>,
    link_target: Option<Vec<u8>>,
}

impl ManifestEntry {
    fn new() -> Self {
        Self{
            file_type: FileType::Unknown,
            path: Vec::new(),
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

        write!(f, "{} {:10} {:10} {:8} {} {}", self.stat.mode, owner, group, size, tstamp, String::from_utf8_lossy(&self.path))?;
        if self.file_type == FileType::SoftLink {
            if let Some(target) = &self.link_target {
                write!(f, " -> {}", String::from_utf8_lossy(&target))?;
            }
            else {
                write!(f, " -> (unknown target)")?;
            }
        }
        Ok(())
    }
}


fn entry_complete(entry: &ManifestEntry) {
    if let Some(_) = entry.link_target {
        println!("{}", entry);
    }
}


fn main() {
    let manifest = File::open("manifest.gz").expect("Could not open manifest");
    let gz = GzDecoder::new(manifest);
    let mut reader = BufReader::new(gz);
    let mut entry = ManifestEntry::new();
    
    let mut line = Vec::new();
    while let Ok(size) = reader.read_until(b'\n', &mut line) {
        if size < 4 {
            println!("short read: {}", size);
            break;
        }

        while (line[line.len() -1] as char).is_whitespace() {
            line.pop();
        }
        let data = &line[5..];
        match line[0] {
            b'r' => entry.stat = Stat::try_from(&data[..]).unwrap(),
            b'f' => {
                entry.file_type = FileType::Plain;
                entry.path = data.to_owned();
            },
            b'd' => {
                entry.file_type = FileType::Directory;
                entry.path = data.to_owned();
                entry_complete(&entry);
                entry = ManifestEntry::new();
            },
            b'l' => {
                if entry.file_type == FileType::SoftLink {
                    entry.link_target = Some(data.to_owned());
                    entry_complete(&entry);
                    entry = ManifestEntry::new();
                }
                else {
                    entry.file_type = FileType::SoftLink;
                    entry.path = data.to_owned();
                }
            },
            b'L' => entry.file_type = FileType::HardLink,
            b't' => entry.data_path = Some(data.to_owned()),
            b'x' => {
                let info = str::from_utf8(data).unwrap();
                let val = info.split(":").collect::<Vec<&str>>();
                entry.size = Some(val[0].parse::<u64>().unwrap());
                entry.md5 = Some(val[1].to_owned());
                entry_complete(&entry);
                entry = ManifestEntry::new();
            },
            _ => println!("Ignoring line starting with '{}'", line[0] as char)
        };
        line.clear();
    }
}
