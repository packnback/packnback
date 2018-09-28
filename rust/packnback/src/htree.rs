use haclstar::sha2_256;
use std::fmt;

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

pub trait Source {
    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, HTreeError>;
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

fn be_bytes_to_u16(hi: u8, lo: u8) -> u16 {
    (u16::from(hi) << 8) | u16::from(lo)
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
        assert!(v.is_empty());
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

        true
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

#[derive(Debug)]
pub enum HTreeError {
    CorruptOrTamperedDataError,
    // This is not an option because it should not really happen.
    DataMissing,
    IOError(std::io::Error),
}

impl fmt::Display for HTreeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HTreeError::CorruptOrTamperedDataError => write!(
                f,
                "The 'htree' data structure input data is not in the expected format or corrupt."
            ),
            HTreeError::DataMissing => {
                write!(f, "The data store does not contain the requested data.")
            }
            HTreeError::IOError(ref e) => e.fmt(f),
        }
    }
}

impl std::error::Error for HTreeError {
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            HTreeError::IOError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HTreeError {
    fn from(err: std::io::Error) -> HTreeError {
        HTreeError::IOError(err)
    }
}

pub struct TreeReader<'a> {
    source: &'a mut Source,
    /* for debug only */
    last_block_parent: Address,
    /* for debug only */
    tree_block_address: Vec<Address>,
    tree_blocks: Vec<Vec<u8>>,
    tree_heights: Vec<u16>,
    read_offsets: Vec<usize>,
}

impl<'a> TreeReader<'a> {
    pub fn new(source: &'a mut Source) -> TreeReader<'a> {
        TreeReader {
            source,
            last_block_parent: [0; ADDRESS_SZ],
            tree_block_address: Vec::new(),
            tree_blocks: Vec::new(),
            tree_heights: Vec::new(),
            read_offsets: Vec::new(),
        }
    }

    fn next_be_16(&mut self) -> Result<u16, HTreeError> {
        let data = self.tree_blocks.last().unwrap();
        let read_offset = self.read_offsets.last_mut().unwrap();
        let remaining = &data[*read_offset..];
        if remaining.len() < 2 {
            return Err(HTreeError::CorruptOrTamperedDataError);
        }
        let v = be_bytes_to_u16(remaining[0], remaining[1]);
        *read_offset += 2;
        Ok(v)
    }

    pub fn push_addr(&mut self, addr: Address) -> Result<(), HTreeError> {
        let data = self.source.get_chunk(addr)?;
        self.tree_block_address.push(addr);
        self.tree_blocks.push(data);
        self.read_offsets.push(0);
        let header_type = self.next_be_16()?;
        if header_type != TYPE_TREE {
            return Err(HTreeError::CorruptOrTamperedDataError);
        }
        let height = self.next_be_16()?;
        self.tree_heights.push(height);
        Ok(())
    }

    fn pop(&mut self) {
        self.tree_block_address.pop();
        self.tree_blocks.pop();
        self.tree_heights.pop();
        self.read_offsets.pop();
    }

    // Returns (Address, is_leaf)
    pub fn next_addr(&mut self) -> Result<Option<(Address, bool)>, HTreeError> {
        loop {
            if self.tree_blocks.is_empty() {
                return Ok(None);
            }

            let parent_addr = self.tree_block_address.last().unwrap();
            let data = self.tree_blocks.last().unwrap();
            let height = self.tree_heights.last().unwrap();
            let read_offset = self.read_offsets.last_mut().unwrap();
            let remaining = &data[*read_offset..];

            if remaining.is_empty() {
                self.pop();
                continue;
            }

            if remaining.len() < ADDRESS_SZ {
                return Err(HTreeError::CorruptOrTamperedDataError);
            }

            let mut result: Address = [0; ADDRESS_SZ];
            result.clone_from_slice(&remaining[0..ADDRESS_SZ]);
            *read_offset += result.len();
            self.last_block_parent = *parent_addr;
            return Ok(Some((result, *height == 0)));
        }
    }

    pub fn next_chunk(&mut self) -> Result<Option<(Address, Vec<u8>)>, HTreeError> {
        loop {
            match self.next_addr()? {
                Some((a, is_leaf)) => {
                    if is_leaf {
                        return Ok(Some((a, self.source.get_chunk(a)?)));
                    } else {
                        self.push_addr(a)?;
                    }
                }
                None => {
                    return Ok(None);
                }
            }
        }
    }

    pub fn get_chunk(&mut self, a: &Address) -> Result<Vec<u8>, HTreeError> {
        self.source.get_chunk(*a)
    }
}

// XXX Do this in a better way, probably format trait.
fn debug_hex_print(buf: &[u8]) {
    for &b in buf {
        print!("{:02X}", b);
    }
}

// XXX Do this in a better way, probably format trait.
// XXX Emit to a writer trait.
pub fn debug_emit_graphvis(source: &mut Source, addr: Address) -> () {
    let mut tr = TreeReader::new(source);
    tr.push_addr(addr).unwrap();

    print!("digraph G {{\nnode [shape=record]\n");
    loop {
        match tr.next_addr().unwrap() {
            Some((a, is_leaf)) => {
                let parent = tr.last_block_parent;

                print!("\"");
                debug_hex_print(&parent);
                print!("\"");
                print!("->");
                print!("\"");
                debug_hex_print(&a);
                print!("\"");
                print!("\n");
                debug_hex_print(&a);
                if is_leaf {
                    print!("\"");
                    debug_hex_print(&a);
                    print!("\"");
                    print!("->");
                    print!("\"");
                    print!("{:?}", tr.get_chunk(&a).unwrap());
                    print!("\"\n");
                } else {
                    tr.push_addr(a).unwrap();
                }
            }
            None => {
                break;
            }
        }
    }
    print!("}}\n");
}

use std::collections::HashMap;

impl<S: ::std::hash::BuildHasher> Sink for HashMap<Address, Vec<u8>, S> {
    fn send_chunk(&mut self, addr: Address, data: Vec<u8>) -> Result<(), std::io::Error> {
        self.insert(addr, data);
        Ok(())
    }
}

impl<S: ::std::hash::BuildHasher> Source for HashMap<Address, Vec<u8>, S> {
    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, HTreeError> {
        if let Some(v) = self.get(&addr) {
            Ok(v.clone())
        } else {
            Err(HTreeError::DataMissing)
        }
    }
}

// XXX Consider making tests table based, lots of repetition?
// Sometimes explicit tests are nice for line numbers and test names.

#[test]
fn test_write_no_level() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Chunks that can only fit two addresses.
    // Split mask that is never successful.
    let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);

    tw.add([1; ADDRESS_SZ], vec![]).unwrap();
    let result = tw.finish().unwrap();

    // root = chunk1
    assert_eq!(chunks.len(), 1);
    let addr_chunk = chunks.get_mut(&result).unwrap();
    assert_eq!(addr_chunk.len(), 0);
}

#[test]
fn test_write_shape_single_level() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Chunks that can only fit two addresses.
    // Split mask is never successful.
    let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);

    tw.add([1; ADDRESS_SZ], vec![]).unwrap();
    tw.add([2; ADDRESS_SZ], vec![0]).unwrap();

    let result = tw.finish().unwrap();

    // One chunk per added. One for addresses.
    // root = [hdr .. chunk1 .. chunk2 ]
    // chunk1, chunk2
    assert_eq!(chunks.len(), 3);
    let addr_chunk = chunks.get_mut(&result).unwrap();
    assert_eq!(addr_chunk.len(), 2 * ADDRESS_SZ + HDR_SZ);
}

#[test]
fn test_write_shape_two_levels() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Chunks that can only fit two addresses.
    // Split mask always is never successful.
    let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);

    tw.add([1; ADDRESS_SZ], vec![]).unwrap();
    tw.add([2; ADDRESS_SZ], vec![0]).unwrap();
    tw.add([3; ADDRESS_SZ], vec![1, 2, 3]).unwrap();

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
fn test_write_shape_single_level_content_split() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Allow large chunks.
    // Split mask always is successful.
    let mut tw = TreeWriter::new(&mut chunks, SENSIBLE_ADDR_MAX_CHUNK_SIZE, [0; 32]);

    tw.add([1; ADDRESS_SZ], vec![]).unwrap();
    tw.add([2; ADDRESS_SZ], vec![0]).unwrap();

    let result = tw.finish().unwrap();

    // One chunk per added. One for addresses.
    // root = [hdr .. chunk1 .. chunk2 ]
    // chunk1, chunk2
    assert_eq!(chunks.len(), 3);
    let addr_chunk = chunks.get_mut(&result).unwrap();
    assert_eq!(addr_chunk.len(), 2 * ADDRESS_SZ + HDR_SZ);
}

#[test]
fn test_write_shape_two_levels_content_split() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    // Allow large chunks.
    // Split mask that is always successful.
    let mut tw = TreeWriter::new(&mut chunks, SENSIBLE_ADDR_MAX_CHUNK_SIZE, [0; 32]);

    tw.add([1; ADDRESS_SZ], vec![]).unwrap();
    tw.add([2; ADDRESS_SZ], vec![0]).unwrap();
    tw.add([3; ADDRESS_SZ], vec![1, 2, 3]).unwrap();

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
fn test_tree_reader_walk() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    let addr: Address;

    {
        // Chunks that can only fit two addresses.
        // Split mask always is never successful.
        let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);
        tw.add([1; ADDRESS_SZ], vec![]).unwrap();
        tw.add([2; ADDRESS_SZ], vec![0]).unwrap();
        tw.add([3; ADDRESS_SZ], vec![1, 2, 3]).unwrap();

        addr = tw.finish().unwrap();
    }

    let mut tr = TreeReader::new(&mut chunks);
    tr.push_addr(addr).unwrap();

    // First address is already counted
    let mut count = 1;
    let mut leaf_count = 0;

    loop {
        match tr.next_addr().unwrap() {
            Some((a, is_leaf)) => {
                count += 1;
                if is_leaf {
                    leaf_count += 1;
                } else {
                    tr.push_addr(a).unwrap();
                }
            }
            None => {
                break;
            }
        }
    }

    // root = [hdr .. address1 .. address2 ]
    // address1 = [hdr .. chunk0 .. chunk1 ]
    // address2 = [hdr .. chunk3 ]
    // chunk0, chunk1, chunk3
    assert_eq!(count, 6);
    assert_eq!(leaf_count, 3);
}

#[test]
fn test_tree_reader_chunks() {
    let mut chunks = HashMap::<Address, Vec<u8>>::new();
    let addr: Address;

    {
        // Chunks that can only fit two addresses.
        // Split mask always is never successful.
        let mut tw = TreeWriter::new(&mut chunks, MINIMUM_ADDR_CHUNK_SIZE, [0xff; 32]);
        tw.add([1; ADDRESS_SZ], vec![]).unwrap();
        tw.add([2; ADDRESS_SZ], vec![0]).unwrap();
        tw.add([3; ADDRESS_SZ], vec![1, 2, 3]).unwrap();

        addr = tw.finish().unwrap();
    }

    let mut tr = TreeReader::new(&mut chunks);
    tr.push_addr(addr).unwrap();

    let (addr, buf) = tr.next_chunk().unwrap().unwrap();
    assert_eq!([1; ADDRESS_SZ], addr);
    assert_eq!(buf, vec![]);
    let (addr, buf) = tr.next_chunk().unwrap().unwrap();
    assert_eq!([2; ADDRESS_SZ], addr);
    assert_eq!(buf, vec![0]);
    let (addr, buf) = tr.next_chunk().unwrap().unwrap();
    assert_eq!([3; ADDRESS_SZ], addr);
    assert_eq!(buf, vec![1, 2, 3]);

    if let Some(_) = tr.next_chunk().unwrap() {
        panic!("expected eof")
    }
}
