pub struct FixedSizeChunker {
    reserve_sz: usize,
    data_sz: usize,
    cur_vec: Vec<u8>,
}

fn read_exact_or_eof(r: &mut std::io::Read, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut buf = buf;
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

fn new_backing_vec(reserve_sz: usize, data_sz: usize) -> Vec<u8> {
    let mut v = Vec::<u8>::with_capacity(reserve_sz + data_sz);
    v.extend(std::iter::repeat(0).take(reserve_sz));
    v
}

impl FixedSizeChunker {
    pub fn new(reserve_sz: usize, data_sz: usize) -> FixedSizeChunker {
        assert!(data_sz != 0);

        FixedSizeChunker {
            reserve_sz,
            data_sz,
            cur_vec: new_backing_vec(reserve_sz, data_sz),
        }
    }

    fn spare_capacity(&self) -> usize {
        self.cur_vec.capacity() - self.cur_vec.len()
    }

    fn swap_vec(&mut self) -> Vec<u8> {
        let mut v = new_backing_vec(self.reserve_sz, self.data_sz);
        std::mem::swap(&mut v, &mut self.cur_vec);
        v
    }

    pub fn add_bytes(&mut self, buf: &[u8]) -> (usize, Option<Vec<u8>>) {
        let n_to_read = std::cmp::min(self.spare_capacity(), buf.len());
        self.cur_vec.extend(buf.iter().take(n_to_read));

        if self.spare_capacity() == 0 {
            (n_to_read, Some(self.swap_vec()))
        } else {
            (n_to_read, None)
        }
    }

    pub fn read_chunk(&mut self, r: &mut std::io::Read) -> Result<Option<Vec<u8>>, std::io::Error> {
        let start_len = self.cur_vec.len();
        // We want to read directly into the current vec to avoid
        // a copy. This should be ok because we are just growing the vec
        // to it's actual capacity in anticipation of a read.
        // On error some uninitialized u8's will be in the trailing end of the buffer,
        // So on error the chunker should not be reused.
        unsafe { self.cur_vec.set_len(self.cur_vec.capacity()) };
        let n_read = read_exact_or_eof(r, &mut self.cur_vec[start_len..])?;
        self.cur_vec.truncate(start_len + n_read);

        if self.spare_capacity() == 0 {
            Ok(Some(self.swap_vec()))
        } else {
            Ok(None)
        }
    }

    pub fn finish(self) -> Option<Vec<u8>> {
        if self.cur_vec.is_empty() {
            None
        } else {
            Some(self.cur_vec)
        }
    }
}

#[test]
fn test_add_bytes() {
    let mut ch = FixedSizeChunker::new(1, 2);

    match ch.add_bytes(b"a") {
        (1, None) => (),
        v => panic!("{:?}", v),
    }

    match ch.add_bytes(b"bc") {
        (1, Some(v)) => assert_eq!(v, b"\0ab"),
        v => panic!("{:?}", v),
    }

    match ch.add_bytes(b"c") {
        (1, None) => (),
        v => panic!("{:?}", v),
    }

    match ch.finish() {
        Some(v) => assert_eq!(v, b"\0c"),
        v => panic!("{:?}", v),
    }
}

#[test]
fn test_read_chunk() {
    use std::io::Cursor;

    let mut ch = FixedSizeChunker::new(1, 2);
    let mut cur = Cursor::new(b"abc");

    match ch.read_chunk(&mut cur).unwrap() {
        Some(v) => assert_eq!(v, b"\0ab"),
        v => panic!("{:?}", v),
    }

    match ch.read_chunk(&mut cur).unwrap() {
        None => (),
        v => panic!("{:?}", v),
    }

    match ch.finish() {
        Some(v) => assert_eq!(v, b"\0c"),
        v => panic!("{:?}", v),
    }
}
