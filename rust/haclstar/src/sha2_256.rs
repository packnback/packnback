extern crate chaclstar;
use chaclstar::sha2_256;

// This sizes are only present in the bindings as a runtime value
// Here we make it a compile time value and must use assert at runtime.
const HACL_SHA2_256_SIZE_STATE: usize = 137;
const HACL_SHA2_256_SIZE_HASH: usize = 32;

#[derive(Clone)]
pub struct Sha2_256 {
    buf: [u8; 64],
    nbuf: usize,
    pub state: [u32; HACL_SHA2_256_SIZE_STATE],
}

impl Sha2_256 {
    pub fn new() -> Sha2_256 {
        unsafe { assert!(sha2_256::Hacl_SHA2_256_size_state as usize == HACL_SHA2_256_SIZE_STATE) };

        let mut st = Sha2_256 {
            buf: [0; 64],
            nbuf: 0,
            state: [0; HACL_SHA2_256_SIZE_STATE],
        };

        unsafe {
            sha2_256::Hacl_SHA2_256_init(st.state.as_mut_ptr());
        };

        st
    }

    pub fn update(&mut self, buf: &[u8]) -> () {
        // XXX Performance optimization, avoid copy
        // when aligned at 64 with update_multi
        // Add benchmarks first...

        for b in buf.iter() {
            self.addb(*b)
        }
    }

    fn addb(&mut self, b: u8) -> () {
        assert!(self.nbuf < 64);
        self.buf[self.nbuf] = b;
        self.nbuf += 1;
        if self.nbuf == 64 {
            self.clear_buf();
        }
    }

    fn clear_buf(&mut self) -> () {
        assert!(self.nbuf == 64);
        unsafe {
            sha2_256::Hacl_SHA2_256_update(self.state.as_mut_ptr(), self.buf.as_mut_ptr());
        };
        self.nbuf = 0;
    }

    pub fn finish(mut self) -> [u8; HACL_SHA2_256_SIZE_HASH] {
        unsafe { assert!(sha2_256::Hacl_SHA2_256_size_hash as usize == HACL_SHA2_256_SIZE_HASH) };
        let mut hash: [u8; HACL_SHA2_256_SIZE_HASH] = [0; HACL_SHA2_256_SIZE_HASH];
        unsafe {
            sha2_256::Hacl_SHA2_256_update_last(
                self.state.as_mut_ptr(),
                self.buf[0..self.nbuf].as_mut_ptr(),
                self.nbuf as u32,
            );
            sha2_256::Hacl_SHA2_256_finish(self.state.as_mut_ptr(), hash.as_mut_ptr());
        };

        hash
    }
}

#[test]
fn test_sha256_zero_size() {
    let mut s = Sha2_256::new();
    s.update(b"");
    assert_eq!(
        s.finish(),
        // python: list(bytearray.fromhex(hashlib.sha256(b"").hexdigest()))
        [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85
        ]
    );
}

#[test]
fn test_sha256_less_than_chunk_size() {
    let mut s = Sha2_256::new();
    s.update(b"xxx");
    assert_eq!(
        s.finish(),
        // python: list(bytearray.fromhex(hashlib.sha256(b"x"*3).hexdigest()))
        [
            205, 46, 176, 131, 124, 155, 76, 150, 44, 34, 210, 255, 139, 84, 65, 183, 180, 88, 5,
            136, 127, 5, 29, 57, 191, 19, 59, 88, 59, 175, 104, 96
        ]
    );
}

#[test]
fn test_sha256_exact_chunk_size() {
    let mut s = Sha2_256::new();
    s.update(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    assert_eq!(
        s.finish(),
        // python list(bytearray.fromhex(hashlib.sha256(b"x"*64).hexdigest()))
        [
            124, 225, 0, 151, 31, 100, 231, 0, 30, 143, 229, 165, 25, 115, 236, 223, 225, 206, 212,
            43, 239, 231, 238, 141, 95, 214, 33, 149, 6, 181, 57, 60
        ]
    );
}

#[test]
fn test_sha256_more_than_chunk_size() {
    let mut s = Sha2_256::new();
    s.update(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    assert_eq!(
        s.finish(),
        // python: list(bytearray.fromhex(hashlib.sha256(b"x"*66).hexdigest()))
        [
            110, 184, 121, 241, 41, 28, 110, 231, 213, 198, 25, 210, 124, 123, 92, 156, 51, 24,
            245, 138, 118, 202, 184, 115, 213, 227, 2, 99, 229, 12, 146, 79
        ]
    );
}

/* TODO
#[bench]
fn bench_1_million_bytes(b: &mut Bencher) {
    let v = vec![1; 1000000];
    let mut s = Sha2_256::new();
    s.update(&v);
    s.finish();
}

#[bench]
fn bench_1_million_bytes_60kb_at_a_time(b: &mut Bencher) {
    TODO
}
*/
