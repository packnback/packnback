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
    ErrorLoadingPublicKey(PathBuf, asymcrypt::AsymcryptError),
    IOError(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StoreError::NotInitializedProperly => {
                write!(f, "The store was not initialized properly.")
            }
            StoreError::StoreDoesNotExist => {
                write!(f, "The store does not exist, did you forget init?.")
            }
            StoreError::ErrorLoadingPublicKey(ref path, ref err) => write!(
                f,
                "Unable to load key at '{}': {}\n",
                path.to_str().unwrap_or("unknown"),
                err
            ),
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

struct FileLock {
    f: fs::File,
}

impl FileLock {
    fn get_exclusive(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::File::open(p)?;
        f.lock_exclusive()?;
        Ok(FileLock { f })
    }

    fn get_shared(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::File::open(p)?;
        f.lock_shared()?;
        Ok(FileLock { f })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.f.unlock();
    }
}

// This handle gets a shared gc.lock
// It allows data append and read.
pub struct ChunkHandle<'a> {
    _gc_lock: FileLock,
    store: &'a PacknbackStore,
}

// This handle gets a shared gc.lock and exclusive store.lock
// It allows editing keys and updating refs.
pub struct ChangeStoreHandle<'a> {
    _gc_lock: FileLock,
    _meta_lock: FileLock,
    store: &'a PacknbackStore,
}

// Does NOT sync the directory. A sync of the directory still needs to be
// done to ensure the atomic rename is persisted.
// That sync can be done once at the end of an 'upload session'.
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
        path_buf.push("store.lock");
        PacknbackStore::check_exists(&path_buf.as_path())?;
        path_buf.pop();
        path_buf.pop();

        Ok(())
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
        path_buf.push("store.lock");
        atomic_add_file_with_parent_sync(path_buf.as_path(), &mut [])?;
        path_buf.pop();
        path_buf.pop();

        PacknbackStore::new(path_buf)
    }

    fn get_lock_path(&self, name: &str) -> PathBuf {
        let mut lock_path = self.store_path.clone();
        lock_path.push("locks");
        lock_path.push(name);
        lock_path
    }

    pub fn chunk_handle<'a>(&'a self) -> Result<ChunkHandle<'a>, StoreError> {
        Ok(ChunkHandle {
            _gc_lock: FileLock::get_shared(&self.get_lock_path("gc.lock"))?,
            store: &self,
        })
    }

    pub fn change_store_handle<'a>(&'a self) -> Result<ChangeStoreHandle<'a>, StoreError> {
        Ok(ChangeStoreHandle {
            _gc_lock: FileLock::get_shared(&self.get_lock_path("gc.lock"))?,
            _meta_lock: FileLock::get_exclusive(&self.get_lock_path("store.lock"))?,
            store: &self,
        })
    }

    pub fn load_master_key(&self) -> Result<asymcrypt::PublicKey, StoreError> {
        let mut master_key_path = self.store_path.clone();
        master_key_path.push("master.pubkey");
        let mut master_key_file = fs::File::open(&master_key_path)?;
        match asymcrypt::PublicKey::read_from(&mut master_key_file) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(StoreError::ErrorLoadingPublicKey(master_key_path, e)),
        }
    }
}

impl<'a> ChangeStoreHandle<'a> {
    pub fn add_public_key(&mut self, pk: &asymcrypt::PublicKey) -> Result<(), StoreError> {
        Ok(())
    }
}

impl<'a> ChunkHandle<'a> {
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
        Ok(())
    }
}

impl<'a> htree::Sink for ChunkHandle<'a> {
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
    let mut tx = store.chunk_handle().unwrap();
    tx.add_chunk(Address::default(), vec![]).unwrap();
    tx.add_chunk(Address::default(), vec![]).unwrap();
    tx.sync().unwrap();

    assert_eq!(store.count_chunks().unwrap(), 1);
}

#[test]
fn test_load_master_pubkey() {
    let tmp_dir = tempdir::TempDir::new("packnback_test_repo").unwrap();
    let k = asymcrypt::Key::new();
    let pk1 = k.pub_key();
    let mut path_buf = PathBuf::from(tmp_dir.path());
    path_buf.push("store");
    let store = PacknbackStore::init(path_buf.as_path(), &k.pub_key()).unwrap();

    let pk2 = store.load_master_key().unwrap();

    assert!(pk1.to_vec() == pk2.to_vec());
}
