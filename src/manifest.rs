use derive_more::{Display, Error};
use std::convert::TryInto;
use std::error::Error;
use std::ffi::OsStr;
use std::io::BufRead;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str;

#[derive(Debug, Display, Error)]
#[display(fmt = "Manifest read error: {}", details)]
pub struct ManifestReadError {
    details: String,
}

impl ManifestReadError {
    /// Create a ManifestReadError, provide details:
    /// ```
    /// use burp::manifest::ManifestReadError;
    /// println!("error: {:?}", ManifestReadError::new("something weird happened"));
    /// ```
    pub fn new(msg: &str) -> Self {
        ManifestReadError {
            details: msg.to_string(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum FileType {
    Unknown,
    Plain,
    Directory,
    SoftLink,
    Metadata,
    Special,
}

pub struct Stat {
    pub containing_device: u64,
    pub inode: u64,
    pub mode: u32,
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
    pub compression: i32,
}

#[derive(Display, Debug, Error)]
#[display(fmt = "Invalid char in base64 string: {}", c)]
struct InvalidBase64Char {
    c: char,
}

/// burp's (or bacula's?) own version of base64 encoding integer types. An encoded value consists
/// of an optional leading '-' for negative values followed by one or more characters from the
/// alphabet. Each character is worth 6 bits, there is no trailing padding.
fn burp_decode_base64(value: &str) -> Result<i64, InvalidBase64Char> {
    let mut result: i64 = 0;
    let mut negative = false;

    let mut val = value;
    // i don't care about leading spaces. do i need to?
    if let Some(stripped) = value.strip_prefix('-') {
        negative = true;
        val = stripped;
    }

    for c in val.chars() {
        result <<= 6;
        match c {
            'A'..='Z' => result += (c as u8 - b'A') as i64,
            'a'..='z' => result += (c as u8 - b'a') as i64 + 26,
            '0'..='9' => result += (c as u8 - b'0') as i64 + 32,
            '+' => result += 62,
            '/' => result += 63,
            _ => return Err(InvalidBase64Char { c }),
        }
    }

    if negative {
        result *= -1;
    }
    Ok(result)
}

impl Stat {
    fn from_burp_string(line: &[u8]) -> Result<Self, Box<dyn Error>> {
        let source = str::from_utf8(line)?;
        let stat = source.split(' ').collect::<Vec<&str>>();
        if stat.len() < 16 {
            return Err(Box::new(ManifestReadError::new(&format!(
                "Too few entries in stat line. Expected 16, found {}",
                stat.len()
            ))));
        }

        Ok(Self {
            containing_device: burp_decode_base64(stat[0])?.try_into()?,
            inode: burp_decode_base64(stat[1])?.try_into()?,
            mode: burp_decode_base64(stat[2])?.try_into()?,
            num_links: burp_decode_base64(stat[3])?.try_into()?,
            owner_id: burp_decode_base64(stat[4])?.try_into()?,
            group_id: burp_decode_base64(stat[5])?.try_into()?,
            device_id: burp_decode_base64(stat[6])?.try_into()?,
            size: burp_decode_base64(stat[7])?.try_into()?,
            blocksize: burp_decode_base64(stat[8])?.try_into()?,
            blocks: burp_decode_base64(stat[9])?.try_into()?,
            access_time: burp_decode_base64(stat[10])?.try_into()?,
            mod_time: burp_decode_base64(stat[11])?.try_into()?,
            change_time: burp_decode_base64(stat[12])?.try_into()?,
            ch_flags: burp_decode_base64(stat[13])?.try_into()?,
            // stat[14] is namen "win_attr" in burp's source code. Never saw this one in real life
            compression: burp_decode_base64(stat[15])?.try_into()?,
        })
    }
}

#[derive(Default)]
pub struct ManifestEntryData {
    pub path: PathBuf,
    pub size: usize,
    pub md5: String,
}

pub struct ManifestEntry {
    file_type: FileType,
    pub path: PathBuf,
    pub stat: Option<Stat>,
    pub data: Option<ManifestEntryData>,
    link_target: Option<PathBuf>,
}

impl ManifestEntry {
    fn new() -> Self {
        Self {
            file_type: FileType::Unknown,
            path: PathBuf::new(),
            stat: None,
            data: None,
            link_target: None,
        }
    }
}

fn add_manifest_line(
    entry: &mut ManifestEntry,
    kind: &char,
    data: &[u8],
) -> Result<bool, Box<dyn Error>> {
    let mut finished = false;

    match kind {
        'r' => entry.stat = Some(Stat::from_burp_string(data)?),
        'm' => {
            entry.file_type = FileType::Metadata;
            entry.path = PathBuf::from(OsStr::from_bytes(data));
        }
        'f' => {
            entry.file_type = FileType::Plain;
            entry.path = PathBuf::from(OsStr::from_bytes(data));
        }
        't' => {
            entry
                .data
                .get_or_insert_with(ManifestEntryData::default)
                .path = PathBuf::from(OsStr::from_bytes(data))
        }
        'L' => {
            // hard links are only relevant on the client side, so we will just ignore them
        }
        's' => {
            entry.file_type = FileType::Special;
            entry.path = PathBuf::from(OsStr::from_bytes(data));
            finished = true;
        }
        'd' => {
            entry.file_type = FileType::Directory;
            entry.path = PathBuf::from(OsStr::from_bytes(data));
            finished = true;
        }
        'l' => {
            if entry.file_type == FileType::SoftLink {
                entry.link_target = Some(PathBuf::from(OsStr::from_bytes(data)));
                finished = true;
            } else {
                entry.file_type = FileType::SoftLink;
                entry.path = PathBuf::from(OsStr::from_bytes(data));
            }
        }
        'x' => {
            let info = str::from_utf8(data)?;
            let mut val = info.split(':');
            entry
                .data
                .get_or_insert_with(ManifestEntryData::default)
                .size = val
                .next()
                .ok_or_else(|| ManifestReadError::new("malformed checksum"))?
                .parse::<usize>()?;
            entry
                .data
                .get_or_insert_with(ManifestEntryData::default)
                .md5 = val
                .next()
                .ok_or_else(|| ManifestReadError::new("malformed checksum"))?
                .to_owned();

            if val.next().is_some() {
                return Err(Box::new(ManifestReadError::new("malformed checksum")));
            }
            finished = true;
        }
        _ => log::debug!("Ignoring line starting with '{}'", *kind as char),
    };

    Ok(finished)
}

struct ManifestLine {
    kind: char,
    data: Vec<u8>,
}

impl ManifestLine {
    fn read<R: BufRead>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let kind = reader.fill_buf()?[0];
        reader.consume(1);

        let mut length_string: [u8; 4] = [0; 4];
        reader.read_exact(&mut length_string)?;
        let data_length = usize::from_str_radix(str::from_utf8(&length_string)?, 16)?;
        let mut data = vec![0_u8; data_length];
        reader.read_exact(&mut data)?;

        // remove trailing line break
        reader.fill_buf()?;
        reader.consume(1);
        Ok(Self {
            kind: kind as char,
            data,
        })
    }
}

pub fn read_manifest<R: BufRead, T, F: FnMut(&ManifestEntry) -> Result<T, Box<dyn Error>>>(
    reader: &mut R,
    callback: &mut F,
) -> Result<(), Box<dyn Error>> {
    let mut entry = ManifestEntry::new();

    let mut entryno = 0;
    loop {
        entryno += 1;
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }

        let line = ManifestLine::read(reader)?;
        match add_manifest_line(&mut entry, &line.kind, &line.data) {
            Ok(false) => (),
            Ok(true) => {
                callback(&entry)?;
                entry = ManifestEntry::new();
            }
            Err(err) => {
                log::debug!("Error in line {}: {:?}", entryno, err);
                return Err(Box::new(ManifestReadError::new(&format!(
                    "{}: Corrupt line in manifest: {:?}",
                    entryno, err
                ))));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_simple() {
        let mut buf = std::io::Cursor::new("a0004ASDF\n");
        let line = ManifestLine::read(&mut buf).unwrap();
        assert_eq!(line.data, b"ASDF");
    }

    #[test]
    fn manifest_short_line() {
        let mut buf = std::io::Cursor::new("t0004a\n"); // length 4 != "a".length()
        let result = ManifestLine::read(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn manifest_entry_invalid_base64() {
        let mut entry = ManifestEntry::new();
        let result = add_manifest_line(&mut entry, &'r', b".");
        assert!(result.is_err());
    }

    #[test]
    fn manifest_entry_invalid_order() {
        let mut entry = ManifestEntry::new();
        let result = add_manifest_line(&mut entry, &'r', b".");
        assert!(result.is_err());
    }

    #[test]
    fn decode_base64() {
        assert_eq!(burp_decode_base64("Po").unwrap(), 1000);
        assert_eq!(burp_decode_base64("-/").unwrap(), -63);
    }

    #[test]
    fn base64_invalid_char() {
        let result = burp_decode_base64(".");
        assert!(result.is_err());
    }

    #[test]
    fn stat_too_short() {
        let stat = Stat::from_burp_string(b"Po");
        assert!(stat.is_err());
    }

    #[test]
    fn parse_stat_line() {
        let stat = Stat::from_burp_string(b"A B C D E F G H I J K L M N O P").unwrap();
        assert_eq!(stat.containing_device, 0);
        assert_eq!(stat.inode, 1);
        assert_eq!(stat.mode, 2);
        assert_eq!(stat.num_links, 3);
        assert_eq!(stat.owner_id, 4);
        assert_eq!(stat.group_id, 5);
        assert_eq!(stat.device_id, 6);
        assert_eq!(stat.size, 7);
        assert_eq!(stat.blocksize, 8);
        assert_eq!(stat.blocks, 9);
        assert_eq!(stat.access_time, 10);
        assert_eq!(stat.mod_time, 11);
        assert_eq!(stat.change_time, 12);
        assert_eq!(stat.ch_flags, 13);
        assert_eq!(stat.compression, 15);
    }

    #[test]
    fn manifest_entry_metadata() {
        let mut entry = ManifestEntry::new();
        let finished = add_manifest_line(&mut entry, &'m', b"some path").unwrap();
        assert_eq!(entry.file_type, FileType::Metadata);
        assert_eq!(entry.path, PathBuf::from("some path"));
        assert!(!finished);
    }

    #[test]
    fn manifest_entry_regular_file() {
        let mut entry = ManifestEntry::new();
        let finished = add_manifest_line(&mut entry, &'f', b"some path").unwrap();
        assert_eq!(entry.file_type, FileType::Plain);
        assert_eq!(entry.path, PathBuf::from("some path"));
        assert!(!finished);
    }

    #[test]
    fn manifest_entry_data_path() {
        let mut entry = ManifestEntry::new();
        let finished = add_manifest_line(&mut entry, &'t', b"some path").unwrap();
        assert_eq!(entry.file_type, FileType::Unknown);
        assert!(entry.data.is_some());
        assert_eq!(entry.data.unwrap().path, PathBuf::from("some path"));
        assert!(!finished);
    }

    #[test]
    fn manifest_entry_special() {
        let mut entry = ManifestEntry::new();
        let finished = add_manifest_line(&mut entry, &'s', b"some path").unwrap();
        assert_eq!(entry.file_type, FileType::Special);
        assert_eq!(entry.path, PathBuf::from("some path"));
        assert!(finished);
    }

    #[test]
    fn manifest_entry_directory() {
        let mut entry = ManifestEntry::new();
        let finished = add_manifest_line(&mut entry, &'d', b"some path").unwrap();
        assert_eq!(entry.file_type, FileType::Directory);
        assert_eq!(entry.path, PathBuf::from("some path"));
        assert!(finished);
    }

    #[test]
    fn manifest_entry_symlink() {
        let mut entry = ManifestEntry::new();
        let mut finished = add_manifest_line(&mut entry, &'l', b"source path").unwrap();
        assert!(!finished);

        finished = add_manifest_line(&mut entry, &'l', b"target path").unwrap();
        assert_eq!(entry.file_type, FileType::SoftLink);
        assert_eq!(entry.path, PathBuf::from("source path"));
        assert_eq!(entry.link_target, Some(PathBuf::from("target path")));
        assert!(finished);
    }

    #[test]
    fn manifest_malformed_checksum() {
        let mut entry = ManifestEntry::new();
        assert!(add_manifest_line(&mut entry, &'x', b"asdf").is_err());
        assert!(add_manifest_line(&mut entry, &'x', b"a:sd:f").is_err());
        assert!(add_manifest_line(&mut entry, &'x', b"asd:f").is_err());

        let finished = add_manifest_line(&mut entry, &'x', b"1234:asdfgh").unwrap();
        assert!(finished);
        assert!(entry.data.is_some());
        let data = entry.data.unwrap();
        assert_eq!(data.size, 1234);
        assert_eq!(data.md5, "asdfgh");
    }
}
