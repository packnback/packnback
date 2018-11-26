use super::address::*;
use std::collections::BTreeMap;
use std::error;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct Metadata {
    pub name: String,
    pub mode: u32,
    pub size: i64,
    pub mtime: i64,
}

pub enum Ent {
    Dir(Dir),
    File(File),
    Lnk(Lnk),
}

pub struct File {
    pub meta: Metadata,
    pub data: Address,
}

pub struct Lnk {
    pub meta: Metadata,
    pub dest: String,
}

pub struct Dir {
    pub meta: Metadata,
    pub ents: BTreeMap<PathBuf, Ent>,
}

#[derive(Debug)]
pub enum IndexingError {
    UnsupportedFileType(PathBuf),
    IOError(std::io::Error),
}

impl fmt::Display for IndexingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IndexingError::UnsupportedFileType(ref p) => write!(
                f,
                "The path {} is of an unsupported type.",
                p.to_str().unwrap_or("unknown")
            ),
            IndexingError::IOError(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for IndexingError {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            IndexingError::IOError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IndexingError {
    fn from(err: std::io::Error) -> IndexingError {
        IndexingError::IOError(err)
    }
}

fn sysmeta2meta(name: String, sysmeta: &fs::Metadata) -> Result<Metadata, IndexingError> {
    Ok(Metadata {
        name: name,
        mode: sysmeta.mode(),
        size: sysmeta.len() as i64,
        mtime: sysmeta
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    })
}

pub fn index_dir<F>(path: &Path, file_to_address: F) -> Result<Dir, IndexingError>
where
    F: Fn(fs::File) -> Result<Address, std::io::Error>,
{
    let sysmeta = fs::metadata(path)?;
    if !sysmeta.file_type().is_dir() {
        return Err(IndexingError::UnsupportedFileType(path.to_path_buf()));
    }

    Ok(Dir {
        meta: sysmeta2meta(
            path.file_name().unwrap().to_str().unwrap().to_string(),
            &sysmeta,
        )?,
        ents: index_dir2(path, &file_to_address)?,
    })
}

fn index_dir2<F>(path: &Path, file_to_address: &F) -> Result<BTreeMap<PathBuf, Ent>, IndexingError>
where
    F: Fn(fs::File) -> Result<Address, std::io::Error>,
{
    let mut ents = BTreeMap::<PathBuf, Ent>::new();

    for e in fs::read_dir(path)? {
        let e = e?;
        let ft = e.file_type()?;
        let sysmeta = &e.metadata()?;
        let name = e.file_name().to_str().unwrap().to_string();
        let ent = if ft.is_symlink() {
            Ent::Lnk(Lnk {
                meta: sysmeta2meta(name, &sysmeta)?,
                dest: fs::read_link(e.path())?.to_str().unwrap().to_string(),
            })
        } else if ft.is_dir() {
            let children = index_dir2(&e.path(), file_to_address)?;
            Ent::Dir(Dir {
                meta: sysmeta2meta(name, &sysmeta)?,
                ents: children,
            })
        } else if ft.is_file() {
            Ent::File(File {
                meta: sysmeta2meta(name, &sysmeta)?,
                data: file_to_address(fs::File::open(e.path())?)?,
            })
        } else {
            continue;
            // return Err(IndexingError::UnsupportedFileType(e.path()));
        };

        ents.insert(e.path(), ent);
    }

    Ok(ents)
}
