use haclstar::sha2_256;

const HDR_SZ: usize = 4;
const ADDRESS_SZ: usize = 32;
const TYPE_TREE: u16 = 0;

// The minimum chunk size is enough for 2 addresses and a header.
pub const MINIMUM_ADDR_CHUNK_SIZE: usize = HDR_SZ + 2 * ADDRESS_SZ;
pub const SENSIBLE_ADDR_MAX_CHUNK_SIZE: usize = HDR_SZ + 30000 * ADDRESS_SZ;

type Address = [u8; 32];

pub trait Sink {
    fn send_chunk(&mut self, addr: Address, data: Vec<u8>) -> Result<(), std::io::Error>;
}

pub trait Store {
    fn get_chunk(&self, addr: Address) -> Result<&[u8], std::io::Error>;
}

pub struct TreeWriter<'a> {
    max_addr_chunk_size: usize,
    split_mask: [u8; 32],
    sink: &'a mut Sink,
    tree_blocks: Vec<Vec<u8>>,
}

fn u16_be_bytes(v: u16) -> (u8, u8) {
    ((((v & 0xff00) >> 8) as u8), (v & 0xff) as u8)
}

impl<'a> TreeWriter<'a> {
    pub fn new(
        sink: &'a mut Sink,
        max_addr_chunk_size: usize,
        split_mask: [u8; ADDRESS_SZ],
    ) -> TreeWriter<'a> {
        assert!(max_addr_chunk_size >= MINIMUM_ADDR_CHUNK_SIZE);
        TreeWriter {
            split_mask,
            max_addr_chunk_size,
            sink,
            tree_blocks: Vec::new(),
        }
    }

    fn write_header(&mut self, level: usize) {
        if level > 0xffff {
            panic!("tree overflow");
        }
        let v = &mut self.tree_blocks[level];
        assert!(v.len() == 0);
        let (type_hi, type_lo) = u16_be_bytes(TYPE_TREE);
        let (height_hi, height_lo) = u16_be_bytes(level as u16);
        v.extend(&[type_hi, type_lo, height_hi, height_lo]);
    }

    fn take_and_clear_level(&mut self, level: usize) -> Vec<u8> {
        let mut block = Vec::with_capacity(MINIMUM_ADDR_CHUNK_SIZE);
        std::mem::swap(&mut block, &mut self.tree_blocks[level]);
        self.write_header(level);
        block
    }

    fn is_split_point(&self, addr: &Address) -> bool {
        assert!(ADDRESS_SZ == self.split_mask.len());

        for i in 0..ADDRESS_SZ {
            let ri = ADDRESS_SZ - 1 - i;
            if (addr[ri] & self.split_mask[ri]) != 0 {
                return false;
            }
        }

        return true;
    }

    fn add_addr(&mut self, level: usize, addr: Address) -> Result<(), std::io::Error> {
        if self.tree_blocks.len() < level + 1 {
            self.tree_blocks.push(Vec::new());
            self.write_header(level);
        }

        assert!(self.tree_blocks[level].len() >= HDR_SZ);
        self.tree_blocks[level].extend(&addr);

        if self.tree_blocks[level].len() >= MINIMUM_ADDR_CHUNK_SIZE {
            let next_would_overflow_max_size =
                self.tree_blocks[level].len() + ADDRESS_SZ > self.max_addr_chunk_size;

            if self.is_split_point(&addr) || next_would_overflow_max_size {
                let current_level_block = self.take_and_clear_level(level);
                let current_block_address: Address = sha2_256::sha2_256(&current_level_block);
                self.sink
                    .send_chunk(current_block_address, current_level_block)?;
                self.add_addr(level + 1, current_block_address)?;
            }
        }

        Ok(())
    }

    pub fn add(&mut self, addr: Address, data: Vec<u8>) -> Result<(), std::io::Error> {
        self.sink.send_chunk(addr, data)?;
        self.add_addr(0, addr)?;
        Ok(())
    }

    fn finish_level(&mut self, level: usize) -> Result<Address, std::io::Error> {
        if self.tree_blocks.len() - 1 == level
            && self.tree_blocks[level].len() == HDR_SZ + ADDRESS_SZ
        {
            // We are the top level, and we only ever got a single address written to us.
            // This block is actually the root address.
            let mut result_addr: Address = [0; 32];
            result_addr.clone_from_slice(&self.tree_blocks[level][HDR_SZ..]);
            return Ok(result_addr);
        }

        assert!(self.tree_blocks[level].len() >= HDR_SZ);
        if self.tree_blocks[level].len() == HDR_SZ {
            // Empty block, writing it to the parent is pointless.
            return self.finish_level(level + 1);
        }

        // The tree blocks must contain whole addresses.
        assert!(((self.tree_blocks[level].len() - HDR_SZ) % ADDRESS_SZ) == 0);

        // Add the current block to the parent.
        let block = self.take_and_clear_level(level);
        let current_block_address: Address = sha2_256::sha2_256(&block);
        self.sink.send_chunk(current_block_address, block)?;
        self.add_addr(level + 1, current_block_address)?;
        Ok(self.finish_level(level + 1)?)
    }

    pub fn finish(mut self) -> Result<Address, std::io::Error> {
        // Its a bug to call finish without adding a single chunk.
        // Either the number of tree_blocks grew larger than 1, or the root
        // block has at at least one address.
        assert!(self.tree_blocks.len() > 1 || self.tree_blocks[0].len() >= HDR_SZ + ADDRESS_SZ);
        Ok(self.finish_level(0)?)
    }
}

use std::collections::HashMap;

impl Sink for HashMap<Address, Vec<u8>> {
    fn send_chunk(&mut self, addr: Address, data: Vec<u8>) -> Result<(), std::io::Error> {
        self.insert(addr, data);
        Ok(())
    }
}

#[test]
fn test_write_single_level() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Chunks that can only fit two addresses.
    // Split mask always is never successful.
    let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);

    tw.add([0; ADDRESS_SZ], vec![]).unwrap();
    tw.add([1; ADDRESS_SZ], vec![0]).unwrap();

    let result = tw.finish().unwrap();

    // One chunk per added. One for addresses.
    // root = [hdr .. chunk1 .. chunk2 ]
    // chunk1, chunk2
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks.get_mut(&[0; ADDRESS_SZ]).unwrap(), &vec![]);
    assert_eq!(chunks.get_mut(&[1; ADDRESS_SZ]).unwrap(), &vec![0]);

    let addr_chunk = chunks.get_mut(&result).unwrap();

    assert_eq!(addr_chunk.len(), 2 * ADDRESS_SZ + HDR_SZ);
}

#[test]
fn test_write_two_levels() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Chunks that can only fit two addresses.
    // Split mask always is never successful.
    let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);

    tw.add([0; ADDRESS_SZ], vec![]).unwrap();
    tw.add([1; ADDRESS_SZ], vec![0]).unwrap();
    tw.add([2; ADDRESS_SZ], vec![1, 2, 3]).unwrap();

    let result = tw.finish().unwrap();

    // root = [hdr .. address1 .. address2 ]
    // address1 = [hdr .. chunk0 .. chunk1 ]
    // address2 = [hdr .. chunk3 ]
    // chunk0, chunk1, chunk3
    assert_eq!(chunks.len(), 6);

    let addr_chunk = chunks.get_mut(&result).unwrap();
    assert_eq!(addr_chunk.len(), 2 * ADDRESS_SZ + HDR_SZ);
}

#[test]
fn test_write_single_level_content_split() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Allow large chunks.
    // Split mask always is successful.
    let mut tw = TreeWriter::new(&mut chunks, SENSIBLE_ADDR_MAX_CHUNK_SIZE, [0; 32]);

    tw.add([0; ADDRESS_SZ], vec![]).unwrap();
    tw.add([1; ADDRESS_SZ], vec![0]).unwrap();

    let result = tw.finish().unwrap();

    // One chunk per added. One for addresses.
    // root = [hdr .. chunk1 .. chunk2 ]
    // chunk1, chunk2
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks.get_mut(&[0; ADDRESS_SZ]).unwrap(), &vec![]);
    assert_eq!(chunks.get_mut(&[1; ADDRESS_SZ]).unwrap(), &vec![0]);

    let addr_chunk = chunks.get_mut(&result).unwrap();

    assert_eq!(addr_chunk.len(), 2 * ADDRESS_SZ + HDR_SZ);
}

#[test]
fn test_write_two_levels_content_split() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Allow large chunks.
    // Split mask that is always successful.
    let mut tw = TreeWriter::new(&mut chunks, SENSIBLE_ADDR_MAX_CHUNK_SIZE, [0; 32]);

    tw.add([0; ADDRESS_SZ], vec![]).unwrap();
    tw.add([1; ADDRESS_SZ], vec![0]).unwrap();
    tw.add([2; ADDRESS_SZ], vec![1, 2, 3]).unwrap();

    let result = tw.finish().unwrap();

    // root = [hdr .. address1 .. address2 ]
    // address1 = [hdr .. chunk0 .. chunk1 ]
    // address2 = [hdr .. chunk3 ]
    // chunk0, chunk1, chunk3
    assert_eq!(chunks.len(), 6);

    let addr_chunk = chunks.get_mut(&result).unwrap();
    assert_eq!(addr_chunk.len(), 2 * ADDRESS_SZ + HDR_SZ);
}
