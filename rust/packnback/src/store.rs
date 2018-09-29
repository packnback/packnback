use super::address::*;
use super::htree;
use std::error;
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

extern crate asymcrypt;
extern crate fs2;
extern crate rand;
extern crate tempdir;

use fs2::FileExt;
use rand::Rng;

#[derive(Debug)]
pub enum StoreError {
    NotInitializedProperly,
    StoreDoesNotExist,
    IOError(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StoreError::NotInitializedProperly => {
                write!(f, "The store was not initialized properly.")
            }
            StoreError::StoreDoesNotExist => {
                write!(f, "The store does not exist, did you forget init?.")
            }
            StoreError::IOError(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for StoreError {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StoreError::IOError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> StoreError {
        StoreError::IOError(err)
    }
}

pub struct PacknbackStore {
    store_path: PathBuf,
    chunk_dir_path: PathBuf,
}

pub struct AddDataTransaction<'a> {
    gc_lock: fs::File,
    store: &'a PacknbackStore,
}

// Does NOT sync the directory. A sync of the directory still needs to be
// done to ensure the atomic rename is persisted.
// That sync can be done once at the end of an 'upload transaction'.
fn atomic_add_file_no_parent_sync(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let temp_path = p
        .to_string_lossy()
        .chars()
        .chain(
            std::iter::repeat(())
                .map(|()| rand::thread_rng().sample(rand::distributions::Alphanumeric))
                .take(10),
        ).chain(".tmp".chars())
        .collect::<String>();

    let mut tmp_file = fs::File::create(&temp_path)?;
    tmp_file.write_all(contents)?;
    tmp_file.sync_all()?;
    std::fs::rename(temp_path, p)?;
    Ok(())
}

fn sync_dir(p: &Path) -> Result<(), std::io::Error> {
    let dir = fs::File::open(p)?;
    dir.sync_all()?;
    Ok(())
}

fn atomic_add_file_with_parent_sync(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    atomic_add_file_no_parent_sync(p, contents)?;
    sync_dir(p.parent().unwrap())?;
    Ok(())
}

fn atomic_add_dir_with_parent_sync(p: &Path) -> Result<(), std::io::Error> {
    fs::DirBuilder::new().create(p)?;
    sync_dir(p.parent().unwrap())?;
    Ok(())
}

impl PacknbackStore {
    fn check_exists(p: &Path) -> Result<(), StoreError> {
        if p.exists() {
            Ok(())
        } else {
            Err(StoreError::NotInitializedProperly)
        }
    }

    fn check_repo_paths(store_path: &Path) -> Result<(), StoreError> {
        if !store_path.exists() {
            return Err(StoreError::StoreDoesNotExist);
        }

        let mut path_buf = PathBuf::from(store_path);

        path_buf.push("chunks");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("roots");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("authorized_keys");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("master.pubkey");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("locks");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.push("gc.lock");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();
        path_buf.push("refs.lock");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();
        path_buf.pop();

        Ok(())
    }

    pub fn count_chunks(&self) -> Result<usize, StoreError> {
        let paths = fs::read_dir(self.chunk_dir_path.as_path())?;
        Ok(paths
            .filter(|e| {
                if let Ok(d) = e {
                    if let Some(oss) = d.path().extension() {
                        oss != "tmp"
                    } else {
                        true
                    }
                } else {
                    false
                }
            }).count())
    }

    pub fn new(store_path: PathBuf) -> Result<PacknbackStore, StoreError> {
        PacknbackStore::check_repo_paths(&store_path.as_path())?;
        let mut chunk_dir_path = store_path.clone();
        chunk_dir_path.push("chunks");
        Ok(PacknbackStore {
            store_path,
            chunk_dir_path,
        })
    }

    pub fn init(
        store_path: &Path,
        master_key: &asymcrypt::PublicKey,
    ) -> Result<PacknbackStore, StoreError> {
        let mut path_buf = PathBuf::from(store_path);

        atomic_add_dir_with_parent_sync(path_buf.as_path())?;

        path_buf.push("chunks");
        atomic_add_dir_with_parent_sync(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("roots");
        atomic_add_dir_with_parent_sync(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("authorized_keys");
        atomic_add_dir_with_parent_sync(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("master.pubkey");
        atomic_add_file_with_parent_sync(path_buf.as_path(), &master_key.to_vec())?;
        path_buf.pop();

        path_buf.push("locks");
        atomic_add_dir_with_parent_sync(path_buf.as_path())?;
        path_buf.push("gc.lock");
        atomic_add_file_with_parent_sync(path_buf.as_path(), &mut [])?;
        path_buf.pop();
        path_buf.push("refs.lock");
        atomic_add_file_with_parent_sync(path_buf.as_path(), &mut [])?;
        path_buf.pop();
        path_buf.pop();

        PacknbackStore::new(path_buf)
    }

    pub fn add_data_transaction<'a>(&'a self) -> Result<AddDataTransaction<'a>, StoreError> {
        let mut gc_lock_path = self.store_path.clone();
        gc_lock_path.push("locks");
        gc_lock_path.push("gc.lock");
        let gc_lock = fs::File::open(gc_lock_path)?;
        gc_lock.lock_shared()?;

        Ok(AddDataTransaction {
            gc_lock,
            store: &self,
        })
    }
}

impl<'a> AddDataTransaction<'a> {
    pub fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), std::io::Error> {
        let mut chunk_path = self.store.chunk_dir_path.clone();
        chunk_path.push(addr.as_hex_addr().as_str());

        if !chunk_path.exists() {
            atomic_add_file_no_parent_sync(chunk_path.as_path(), &buf)?;
        }
        Ok(())
    }

    pub fn sync(self) -> Result<(), StoreError> {
        sync_dir(self.store.chunk_dir_path.as_path())?;
        self.gc_lock.unlock()?;
        Ok(())
    }
}

impl<'a> htree::Sink for AddDataTransaction<'a> {
    fn send_chunk(&mut self, addr: Address, data: Vec<u8>) -> Result<(), std::io::Error> {
        self.add_chunk(addr, data)
    }
}

#[test]
fn add_chunk() {
    let tmp_dir = tempdir::TempDir::new("packnback_test_repo").unwrap();
    let k = asymcrypt::Key::new();

    let mut path_buf = PathBuf::from(tmp_dir.path());
    path_buf.push("store");
    let store = PacknbackStore::init(path_buf.as_path(), &k.pub_key()).unwrap();
    let mut tx = store.add_data_transaction().unwrap();
    tx.add_chunk(Address::default(), vec![]).unwrap();
    tx.add_chunk(Address::default(), vec![]).unwrap();
    tx.sync().unwrap();

    assert_eq!(store.count_chunks().unwrap(), 1);
}
