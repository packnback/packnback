extern crate chaclstar;
extern crate rand;

use chaclstar::nacl;
use rand::{OsRng, RngCore};

pub const CRYPTO_SIGN_BYTES: usize = nacl::crypto_sign_BYTES as usize;
pub const CRYPTO_BOX_ZEROBYTES: usize = nacl::crypto_box_ZEROBYTES as usize;
pub const CRYPTO_BOX_BOXZEROBYTES: usize = nacl::crypto_box_BOXZEROBYTES as usize;

#[derive(Clone, Default)]
pub struct CryptoBoxNonce {
    pub bytes: [u8; nacl::crypto_box_NONCEBYTES as usize],
}

impl CryptoBoxNonce {
    pub fn new() -> CryptoBoxNonce {
        let mut n: CryptoBoxNonce = Default::default();
        let mut rng = OsRng::new().expect("Error opening random number generator");
        rng.fill_bytes(&mut n.bytes[..]);
        n
    }

    pub fn inc(&mut self) {
        for x in 0..self.bytes.len() {
            let b = self.bytes[x].wrapping_add(1);
            self.bytes[x] = b;
            if b != 0 {
                break;
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct CryptoBoxPk {
    pub bytes: [u8; nacl::crypto_box_PUBLICKEYBYTES as usize],
}

#[derive(Default)]
pub struct CryptoBoxSk {
    pub bytes: [u8; nacl::crypto_box_SECRETKEYBYTES as usize],
}

impl Drop for CryptoBoxSk {
    fn drop(&mut self) {
        // XXX This may be optimized away, how to ensure wiping of memory
        // It is not totally critical but nice to have.
        self.bytes = [0; nacl::crypto_box_SECRETKEYBYTES as usize];
    }
}

pub fn crypto_box_keypair() -> (CryptoBoxPk, Box<CryptoBoxSk>) {
    let mut pk: CryptoBoxPk = Default::default();
    let mut sk = Box::<CryptoBoxSk>::new(Default::default());
    unsafe {
        assert!(0 == nacl::crypto_box_keypair(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()));
    }
    (pk, sk)
}

#[derive(Clone, Default)]
pub struct CryptoSignPk {
    pub bytes: [u8; nacl::crypto_sign_PUBLICKEYBYTES as usize],
}

pub struct CryptoSignSk {
    pub bytes: [u8; nacl::crypto_sign_SECRETKEYBYTES as usize],
}

impl Default for CryptoSignSk {
    fn default() -> CryptoSignSk {
        CryptoSignSk {
            bytes: [0; nacl::crypto_sign_SECRETKEYBYTES as usize],
        }
    }
}

impl Drop for CryptoSignSk {
    fn drop(&mut self) {
        // XXX This may be optimized away, how to ensure wiping of memory
        // It is not totally critical but nice to have.
        self.bytes = [0; nacl::crypto_sign_SECRETKEYBYTES as usize];
    }
}

pub fn crypto_sign_keypair() -> (CryptoSignPk, Box<CryptoSignSk>) {
    let mut pk: CryptoSignPk = Default::default();
    let mut sk = Box::<CryptoSignSk>::new(Default::default());
    unsafe {
        assert!(0 == nacl::crypto_sign_keypair(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()));
    }
    (pk, sk)
}

pub fn crypto_sign(sm: &mut [u8], m: &[u8], sk: &CryptoSignSk) -> usize {
    // Contract from nacl api.
    assert!(sm.len() >= m.len() + nacl::crypto_sign_BYTES as usize);

    let mut smsz: u64 = 0;

    unsafe {
        assert!(
            0 == nacl::crypto_sign(
                sm.as_mut_ptr(),
                &mut smsz,
                m.as_ptr(),
                m.len() as u64,
                sk.bytes.as_ptr()
            )
        );
    }

    smsz as usize
}

pub fn crypto_sign_open(m: &mut [u8], sm: &[u8], pk: &CryptoSignPk) -> Option<usize> {
    assert!(m.len() >= sm.len());

    let mut msz: u64 = 0;

    let rc = unsafe {
        nacl::crypto_sign_open(
            m.as_mut_ptr(),
            &mut msz,
            sm.as_ptr(),
            sm.len() as u64,
            pk.bytes.as_ptr(),
        )
    };

    if rc != 0 {
        None
    } else {
        Some(msz as usize)
    }
}

pub fn crypto_box(c: &mut [u8], m: &[u8], n: &CryptoBoxNonce, pk: &CryptoBoxPk, sk: &CryptoBoxSk) {
    // Contract from nacl api.
    assert!(c.len() >= m.len());
    assert!(m.len() >= nacl::crypto_box_ZEROBYTES as usize);
    for b in m.iter().take(nacl::crypto_box_ZEROBYTES as usize) {
        assert!(*b == 0);
    }

    unsafe {
        assert!(
            0 == nacl::crypto_box(
                c.as_mut_ptr(),
                m.as_ptr(),
                m.len() as u64,
                n.bytes.as_ptr(),
                pk.bytes.as_ptr(),
                sk.bytes.as_ptr()
            )
        );
    }
}

pub fn crypto_box_open(
    m: &mut [u8],
    c: &[u8],
    n: &CryptoBoxNonce,
    pk: &CryptoBoxPk,
    sk: &CryptoBoxSk,
) -> bool {
    // Contract from nacl api.
    assert!(m.len() >= c.len());
    assert!(c.len() >= nacl::crypto_box_BOXZEROBYTES as usize);

    for b in m.iter().take(nacl::crypto_box_BOXZEROBYTES as usize) {
        assert!(*b == 0);
    }

    unsafe {
        0 == nacl::crypto_box_open(
            m.as_mut_ptr(),
            c.as_ptr(),
            c.len() as u64,
            n.bytes.as_ptr(),
            pk.bytes.as_ptr(),
            sk.bytes.as_ptr(),
        )
    }
}

// Tests --------------------

#[test]
fn test_crypto_box() {
    const MSIZE: usize = (nacl::crypto_box_BOXZEROBYTES + 128) as usize;
    let mut m1: [u8; MSIZE] = [3; MSIZE];
    let mut m2: [u8; MSIZE] = [0; MSIZE];
    let mut c: [u8; MSIZE] = [0; MSIZE];

    let (pk, sk) = crypto_box_keypair();
    let n = CryptoBoxNonce::new();

    for i in 0..nacl::crypto_box_ZEROBYTES {
        m1[i as usize] = 0;
    }
    crypto_box(&mut c[..], &m1, &n, &pk, &sk);

    for i in 0..(nacl::crypto_box_BOXZEROBYTES as usize) {
        assert!(c[i] == 0);
    }

    assert!(crypto_box_open(&mut m2[..], &c, &n, &pk, &sk));
    assert_eq!(
        m1[(nacl::crypto_box_ZEROBYTES as usize)..],
        m2[(nacl::crypto_box_ZEROBYTES as usize)..]
    );

    // corrupt/tamper
    let corrupt_at = (nacl::crypto_box_BOXZEROBYTES + 1) as usize;
    c[corrupt_at] = !c[corrupt_at];
    assert!(crypto_box_open(&mut m2[..], &c, &n, &pk, &sk) == false);
}

#[test]
fn test_crypto_sign() {
    const MSIZE: usize = 32;
    const SMSIZE: usize = MSIZE + (nacl::crypto_sign_BYTES as usize);
    let m1: [u8; MSIZE] = [3; MSIZE];
    let mut m2: [u8; SMSIZE] = [0; SMSIZE];
    let mut sm: [u8; SMSIZE] = [0; SMSIZE];
    let (pk, sk) = crypto_sign_keypair();
    let smsz = crypto_sign(&mut sm[..], &m1, &sk);
    let m2sz = crypto_sign_open(&mut m2[..], &sm[..smsz], &pk).unwrap();
    assert_eq!(m1, m2[0..m2sz]);
}

#[test]
fn test_nonce_inc() {
    let mut n = CryptoBoxNonce::new();
    n.bytes[0] = 0xff;
    n.bytes[1] = 0xff;
    n.bytes[2] = 0xfe;
    n.bytes[3] = 3;
    n.inc();
    assert!(n.bytes[0] == 0);
    assert!(n.bytes[1] == 0);
    assert!(n.bytes[2] == 0xff);
    assert!(n.bytes[3] == 3);
}
