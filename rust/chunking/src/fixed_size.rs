pub struct FixedSizeChunker {
    sz: usize,
    cur_vec: Box<Vec<u8>>,
}

impl FixedSizeChunker {
    pub fn new(sz: usize) -> FixedSizeChunker {
        assert!(sz != 0);

        FixedSizeChunker {
            sz: sz,
            cur_vec: Box::new(Vec::<u8>::with_capacity(sz)),
        }
    }

    pub fn add_bytes(&mut self, buf: &[u8]) -> (usize, Option<Box<Vec<u8>>>) {
        let spare_capacity = self.cur_vec.capacity() - self.cur_vec.len();
        let n_to_read = std::cmp::min(spare_capacity, buf.len());
        self.cur_vec.extend(buf.iter().take(n_to_read));

        if self.cur_vec.len() == self.sz {
            let mut v = Box::new(Vec::<u8>::with_capacity(self.sz));
            std::mem::swap(&mut v, &mut self.cur_vec);
            assert!(v.len() == self.sz);
            (n_to_read, Some(v))
        } else {
            (n_to_read, None)
        }
    }

    pub fn finish(self) -> Option<Box<Vec<u8>>> {
        if self.cur_vec.len() == 0 {
            None
        } else {
            assert!(self.cur_vec.len() < self.sz);
            Some(self.cur_vec)
        }
    }
}
