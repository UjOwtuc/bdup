use burp::manifest;
use std::fs;
use std::io;
use std::path::PathBuf;

#[test]
fn read_manifest_error() {
    let mut reader = io::Cursor::new("r0016unreadable stat string\n");
    assert!(manifest::read_manifest(&mut reader, &mut |_| Ok(())).is_err());
}

#[test]
fn read_manifest() {
    let manifest = fs::File::open("tests/manifest").unwrap();
    let mut reader = io::BufReader::new(manifest);

    let mut entries: Vec<manifest::ManifestEntry> = Vec::new();
    let result = manifest::read_manifest(&mut reader, &mut |entry: manifest::ManifestEntry| {
        entries.push(entry);
        Ok(())
    });

    assert!(result.is_ok());
    assert_eq!(entries.len(), 4); // regular file, hard link (ignored), directory, metadata, symlink

    let mut iter = entries.iter();
    assert_eq!(
        iter.next().unwrap().path,
        PathBuf::from("/simple/file/path")
    );
    assert_eq!(
        iter.next().unwrap().path,
        PathBuf::from("/some/directory/path")
    );
    assert_eq!(
        iter.next().unwrap().path,
        PathBuf::from("/metadata/file/path")
    );
    assert_eq!(
        iter.next().unwrap().path,
        PathBuf::from("/usr/lib/x86_64-linux-gnu/libEGL_mesa.so.0")
    );
}
