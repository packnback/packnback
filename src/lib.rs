extern crate rand;
use rand::OsRng;
use rand::RngCore;

#[allow(non_upper_case_globals)]
#[allow(dead_code)]
mod bindings;
use self::bindings::*;

#[derive(Default)]
pub struct CryptoBoxNonce {
    pub bytes: [u8; crypto_box_curve25519xsalsa20poly1305_NONCEBYTES as usize],
}

impl CryptoBoxNonce {
    pub fn new() -> CryptoBoxNonce {
        let mut n: CryptoBoxNonce = Default::default();
        let mut rng = OsRng::new().expect("Error opening random number generator");
        rng.fill_bytes(&mut n.bytes[..]);
        n
    }
}

#[derive(Default)]
pub struct CryptoBoxPk {
    pub bytes: [u8; crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES as usize],
}

#[derive(Default)]
pub struct CryptoBoxSk {
    pub bytes: [u8; crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES as usize],
}

impl Drop for CryptoBoxSk {
    fn drop(&mut self) {
        // XXX This may be optimized away, how to ensure wiping of memory
        // It is not totally critical but nice to have.
        self.bytes = [0; crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES as usize];
    }
}

pub fn crypto_box_keypair(pk: &mut CryptoBoxPk, sk: &mut CryptoBoxSk) {
    unsafe {
        assert!(
            0 == crypto_box_curve25519xsalsa20poly1305_tweet_keypair(
                pk.bytes.as_mut_ptr(),
                sk.bytes.as_mut_ptr()
            )
        );
    }
}

pub fn boxed_crypto_box_keypair() -> (Box<CryptoBoxPk>, Box<CryptoBoxSk>) {
    let mut pk = Box::<CryptoBoxPk>::new(Default::default());
    let mut sk = Box::<CryptoBoxSk>::new(Default::default());
    crypto_box_keypair(&mut *pk, &mut *sk);
    (pk, sk)
}

// Defined for tweetnacl to call.
#[no_mangle]
pub extern "C" fn randombytes(p: *mut u8, sz: usize) -> usize {
    let mut rng = OsRng::new().expect("Error opening random number generator");
    let buf = unsafe { std::slice::from_raw_parts_mut(p, sz) };
    rng.fill_bytes(buf);
    0
}

// Tests

#[test]
fn test_boxed_crypto_box_keypair() {
    // XXX remove once encrypt/decrypt are tested
    let (_, _) = boxed_crypto_box_keypair();
}
