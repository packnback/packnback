extern crate haclstar;
use haclstar::nacl::*;
use haclstar::sha2_256::*;
use std::error;
use std::fmt;

#[derive(Default)]
pub struct Key {
    pub box_sk: Box<CryptoBoxSk>,
    pub box_pk: CryptoBoxPk,
    pub sign_sk: Box<CryptoSignSk>,
    pub sign_pk: CryptoSignPk,
}

#[derive(Default)]
pub struct PublicKey {
    pub box_pk: CryptoBoxPk,
    pub sign_pk: CryptoSignPk,
}

type KeyID = [u8; 32];

impl Key {
    pub fn new() -> Key {
        let (box_pk, box_sk) = crypto_box_keypair();
        let (sign_pk, sign_sk) = crypto_sign_keypair();
        Key {
            box_pk,
            box_sk,
            sign_pk,
            sign_sk,
        }
    }

    pub fn id(&self) -> KeyID {
        let mut s = Sha2_256::new();
        s.update(&self.box_pk.bytes);
        s.update(&self.sign_pk.bytes);
        s.finish()
    }

    pub fn pub_key(&self) -> PublicKey {
        PublicKey {
            box_pk: self.box_pk.clone(),
            sign_pk: self.sign_pk.clone(),
        }
    }

    pub fn write(&self, w: &mut std::io::Write) -> Result<(), std::io::Error> {
        write_header(w, KEYHEADER)?;
        w.write_all(&self.box_pk.bytes)?;
        w.write_all(&self.box_sk.bytes)?;
        w.write_all(&self.sign_pk.bytes)?;
        w.write_all(&self.sign_sk.bytes)?;
        Ok(())
    }

    pub fn read_boxed_from(r: &mut std::io::Read) -> Result<Key, AsymcryptError> {
        expect_header(r, KEYHEADER)?;
        let mut k: Key = Default::default();
        r.read_exact(&mut k.box_pk.bytes)?;
        r.read_exact(&mut k.box_sk.bytes)?;
        r.read_exact(&mut k.sign_pk.bytes)?;
        r.read_exact(&mut k.sign_sk.bytes)?;
        Ok(k)
    }
}

impl PublicKey {
    pub fn id(&self) -> KeyID {
        let mut s = Sha2_256::new();
        s.update(&self.box_pk.bytes);
        s.update(&self.sign_pk.bytes);
        s.finish()
    }

    pub fn write(&self, w: &mut std::io::Write) -> Result<(), std::io::Error> {
        write_header(w, PUBKEYHEADER)?;
        w.write_all(&self.box_pk.bytes)?;
        w.write_all(&self.sign_pk.bytes)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum AsymcryptError {
    InvalidDataError,
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
            AsymcryptError::InvalidDataError => {
                write!(f, "The input data is not in the expected format.")
            }
            AsymcryptError::UnsupportedVersionError => {
                write!(f, "Unsupported encrypted/signed data version.")
            }
            AsymcryptError::UnexpectedDataTypeError => {
                write!(f, "The given data is of an unexpected cryptographic type.")
            }
            AsymcryptError::DecryptKeyMismatchError => {
                write!(f, "The given key cannot decrypt the given data.")
            }
            AsymcryptError::SignatureKeyMismatchError => {
                write!(f, "The given key did not create the given signature.")
            }
            AsymcryptError::SignatureFailedError => write!(f, "The digital signature has failed."),
            AsymcryptError::CorruptOrTamperedDataError => {
                write!(f, "Decrypting found corrupt or tampered with data.")
            }
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

impl From<std::io::Error> for AsymcryptError {
    fn from(err: std::io::Error) -> AsymcryptError {
        AsymcryptError::IOError(err)
    }
}

type AsymcryptHeaderType = u16;

const KEYHEADER: AsymcryptHeaderType = 0;
const PUBKEYHEADER: AsymcryptHeaderType = 1;
const SIGNATUREHEADER: AsymcryptHeaderType = 2;
const CIPHERTEXTHEADER: AsymcryptHeaderType = 3;
const HEADEREND: AsymcryptHeaderType = 4;

fn u16_to_header_type(t: u16) -> Option<AsymcryptHeaderType> {
    if t < HEADEREND {
        Some(t as AsymcryptHeaderType)
    } else {
        None
    }
}

fn u16_be_bytes(v: u16) -> (u8, u8) {
    ((((v & 0xff00) >> 8) as u8), (v & 0xff) as u8)
}

fn be_bytes_to_u16(hi: u8, lo: u8) -> u16 {
    (u16::from(hi) << 8) | u16::from(lo)
}

const MAGIC_LEN: usize = 9;

fn write_header(
    w: &mut std::io::Write,
    val_type: AsymcryptHeaderType,
) -> Result<(), std::io::Error> {
    let magic = "asymcrypt";
    assert!(MAGIC_LEN == magic.len());
    w.write_all(magic.as_bytes())?;
    let (ver_hi, ver_lo) = u16_be_bytes(2);
    let (type_hi, type_lo) = u16_be_bytes(val_type as u16);
    let ver_and_val = [ver_hi, ver_lo, type_hi, type_lo];
    w.write_all(&ver_and_val[..])
}

fn read_header(r: &mut std::io::Read) -> Result<AsymcryptHeaderType, AsymcryptError> {
    let magic = "asymcrypt";
    let mut magic_buf: [u8; MAGIC_LEN] = [0; MAGIC_LEN];
    assert!(MAGIC_LEN == magic.len());

    let mut ver_and_val = [0; 4];
    r.read_exact(&mut magic_buf)?;
    if magic.as_bytes() != magic_buf {
        return Err(AsymcryptError::InvalidDataError);
    }
    r.read_exact(&mut ver_and_val)?;

    let ver = be_bytes_to_u16(ver_and_val[0], ver_and_val[1]);
    let val_type = be_bytes_to_u16(ver_and_val[2], ver_and_val[3]);

    match (ver, u16_to_header_type(val_type)) {
        (2, Some(t)) => Ok(t),
        (2, None) => Err(AsymcryptError::InvalidDataError),
        _ => Err(AsymcryptError::UnsupportedVersionError),
    }
}

fn expect_header(
    r: &mut std::io::Read,
    val_type: AsymcryptHeaderType,
) -> Result<(), AsymcryptError> {
    let read_val_type = read_header(r)?;
    if read_val_type == val_type {
        Ok(())
    } else {
        Err(AsymcryptError::UnexpectedDataTypeError)
    }
}

fn read_exact_or_eof(r: &mut std::io::Read, mut buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut n: usize = 0;
    loop {
        match r.read(buf)? {
            0 => return Ok(n),
            n_read => {
                n += n_read;
                buf = &mut buf[n_read..];
            }
        }
    }
}

const DATA_BLOCK_SZ: usize = 16384;

pub fn encrypt(
    in_data: &mut std::io::Read,
    out_data: &mut std::io::Write,
    to_key: &PublicKey,
) -> Result<(), std::io::Error> {
    const BUF_SZ: usize = CRYPTO_BOX_ZEROBYTES + 2 + DATA_BLOCK_SZ;
    let mut plain_text: [u8; BUF_SZ] = [0; BUF_SZ];
    let mut cipher_text: [u8; BUF_SZ] = [0; BUF_SZ];
    let mut nonce = CryptoBoxNonce::new();
    let (ephemeral_pk, ephemeral_sk) = crypto_box_keypair();

    write_header(out_data, CIPHERTEXTHEADER)?;
    out_data.write_all(&ephemeral_pk.bytes)?;
    out_data.write_all(&to_key.id())?;
    out_data.write_all(&nonce.bytes)?;

    loop {
        match read_exact_or_eof(in_data, &mut plain_text[CRYPTO_BOX_ZEROBYTES + 2..])? {
            0 => {
                break;
            }
            n => {
                assert!(n <= 0xffff);
                let (sz_hi, sz_lo) = u16_be_bytes(n as u16);
                plain_text[CRYPTO_BOX_ZEROBYTES] = sz_hi;
                plain_text[CRYPTO_BOX_ZEROBYTES + 1] = sz_lo;
                crypto_box(
                    &mut cipher_text,
                    &plain_text,
                    &nonce,
                    &to_key.box_pk,
                    &ephemeral_sk,
                );
                out_data.write_all(&cipher_text[CRYPTO_BOX_BOXZEROBYTES..])?;
            }
        }

        nonce.inc();
    }

    Ok(())
}

pub fn decrypt(
    in_data: &mut std::io::Read,
    out_data: &mut std::io::Write,
    key: &Key,
) -> Result<(), AsymcryptError> {
    const BUF_SZ: usize = CRYPTO_BOX_ZEROBYTES + 2 + DATA_BLOCK_SZ;
    let mut plain_text: [u8; BUF_SZ] = [0; BUF_SZ];
    let mut cipher_text: [u8; BUF_SZ] = [0; BUF_SZ];

    let mut recipient_kid: KeyID = [0; 32];
    let mut ephemeral_pk: CryptoBoxPk = Default::default();
    let mut nonce: CryptoBoxNonce = Default::default();

    expect_header(in_data, CIPHERTEXTHEADER)?;
    in_data.read_exact(&mut ephemeral_pk.bytes)?;
    in_data.read_exact(&mut recipient_kid)?;
    in_data.read_exact(&mut nonce.bytes)?;

    if recipient_kid != key.id() {
        return Err(AsymcryptError::DecryptKeyMismatchError);
    }

    loop {
        in_data.read_exact(&mut cipher_text[CRYPTO_BOX_BOXZEROBYTES..])?;

        if !crypto_box_open(
            &mut plain_text,
            &cipher_text,
            &nonce,
            &ephemeral_pk,
            &key.box_sk,
        ) {
            return Err(AsymcryptError::CorruptOrTamperedDataError);
        }

        let msz = be_bytes_to_u16(plain_text[0], plain_text[1]) as usize;

        out_data.write_all(&plain_text[2..2 + msz])?;
        nonce.inc();

        if msz != DATA_BLOCK_SZ + 2 {
            break;
        }
    }

    Ok(())
}

#[test]
fn test_encrypt_decrypt() {
    use std::io::Cursor;

    // Large enough to loop multiple times
    const SZ: usize = 100000;

    let key = Key::new();
    let mut pt_cursor = Cursor::new(vec![2; SZ]);
    let mut ct_cursor = Cursor::new(Vec::new());

    encrypt(&mut pt_cursor, &mut ct_cursor, &key.pub_key()).unwrap();

    pt_cursor.set_position(0);
    ct_cursor.set_position(0);

    decrypt(&mut ct_cursor, &mut pt_cursor, &key).unwrap();

    let pt = pt_cursor.get_ref();

    for i in 0..SZ {
        assert_eq!(pt[i], 2);
    }
}

#[test]
fn test_encrypt_decrypt_tampered() {
    use std::io::Cursor;

    const SZ: usize = 200;

    let key = Key::new();
    let mut pt_cursor = Cursor::new(vec![2; SZ]);
    let mut ct_cursor = Cursor::new(Vec::new());

    encrypt(&mut pt_cursor, &mut ct_cursor, &key.pub_key()).unwrap();

    pt_cursor.set_position(0);
    ct_cursor.set_position(0);

    let ct = ct_cursor.get_mut();
    ct[100] = !ct[100];

    match decrypt(&mut ct_cursor, &mut pt_cursor, &key) {
        Err(AsymcryptError::CorruptOrTamperedDataError) => (),
        v => {
            println!("{:?}", v);
            panic!(v)
        }
    }
}

#[test]
fn test_encrypt_decrypt_wrong_key() {
    use std::io::Cursor;

    const SZ: usize = 200;

    let key = Key::new();
    let mut pt_cursor = Cursor::new(vec![2; SZ]);
    let mut ct_cursor = Cursor::new(Vec::new());

    encrypt(&mut pt_cursor, &mut ct_cursor, &key.pub_key()).unwrap();

    let key = Key::new();

    pt_cursor.set_position(0);
    ct_cursor.set_position(0);

    match decrypt(&mut ct_cursor, &mut pt_cursor, &key) {
        Err(AsymcryptError::DecryptKeyMismatchError) => (),
        v => {
            println!("{:?}", v);
            panic!(v)
        }
    }
}
