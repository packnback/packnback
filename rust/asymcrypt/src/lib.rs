extern crate tweetnacl;
use std::error;
use std::fmt;
use tweetnacl::*;

#[derive(Default)]
pub struct Key {
    pub box_sk: CryptoBoxSk,
    pub box_pk: CryptoBoxPk,
    pub sign_sk: CryptoSignSk,
    pub sign_pk: CryptoSignPk,
}

#[derive(Default)]
pub struct PublicKey {
    pub box_pk: CryptoBoxPk,
    pub sign_pk: CryptoSignPk,
}

impl Key {
    pub fn new() -> Box<Key> {
        let mut k = Box::<Key>::new(Default::default());
        crypto_box_keypair(&mut k.box_pk, &mut k.box_sk);
        crypto_sign_keypair(&mut k.sign_pk, &mut k.sign_sk);
        k
    }

    pub fn pub_key(&self) -> PublicKey {
        PublicKey {
            box_pk: self.box_pk.clone(),
            sign_pk: self.sign_pk.clone(),
        }
    }
}

#[derive(Debug)]
pub enum AsymcryptError {
  UnsupportedVersionError,
  UnexpectedDataTypeError,
  DecryptKeyMismatchError,
  SignatureKeyMismatchError,
  SignatureFailedError,
  CorruptOrTamperedDataError,
  IOError(std::io::Error),
}

impl fmt::Display for AsymcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AsymcryptError::UnsupportedVersionError => write!(f, "Unsupported encrypted/signed data version."),
            AsymcryptError::UnexpectedDataTypeError => write!(f, "The given data is of an unexpected cryptographic type."),
            AsymcryptError::DecryptKeyMismatchError => write!(f, "The given key cannot decrypt the given data."),
            AsymcryptError::SignatureKeyMismatchError => write!(f, "The given key did not create the given signature."),
            AsymcryptError::SignatureFailedError => write!(f, "The digital signature has failed."),
            AsymcryptError::CorruptOrTamperedDataError => write!(f, "Decrypting found corrupt or tampered with data."),
            AsymcryptError::IOError(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for AsymcryptError {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AsymcryptError::IOError(ref e) => Some(e),
            _ => None,
        }
    }
}

enum AsymcryptHeaderType {
  KeyHeader,
  PubKeyHeader,
  CipherTextHeader,
}

impl AsymcryptHeaderType {
  fn as_u16(&self) -> u16 {
    match self {
    AsymcryptHeaderType::KeyHeader => 0,
    AsymcryptHeaderType::PubKeyHeader => 1,
    AsymcryptHeaderType::CipherTextHeader => 2,
    }
  }

  fn from_u16(v: u16) -> Option<AsymcryptHeaderType> {
    match v {
    0 => Some(AsymcryptHeaderType::KeyHeader),
    1 => Some(AsymcryptHeaderType::PubKeyHeader),
    2 => Some(AsymcryptHeaderType::CipherTextHeader),
    _ => None
    }
  }
}

fn u16_be_bytes(v: u16) -> (u8, u8) {
  ((((v & 0xff00) >> 8) as u8), (v & 0xff) as u8)
}

fn write_header(w: &mut std::io::Write, version: u16, val_type: AsymcryptHeaderType) -> Result<(), std::io::Error> {
    w.write_all("asymcrypt".as_bytes())?;
    let (a,b) = u16_be_bytes(version);
    let (c,d) = u16_be_bytes(val_type.as_u16());
    let ver_and_val = [a,b,c,d];
    w.write_all(&ver_and_val[..])
}

/*
fn read_header(w: &mut std::io::Read) -> Result<(u16, u16), std::io::Error> {
    w.write_all("asymcrypt".as_bytes())?;
    let ver_and_val = [
        (((version & 0xff00) >> 8) as u8),
        (version & 0xff) as u8,
        (((val_type & 0xff00) >> 8) as u8),
        (val_type & 0xff) as u8,
    ];
    w.write_all(&ver_and_val[..])
}
*/