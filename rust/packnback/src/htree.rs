const HDR_SZ: usize = 3;
const ADDRESS_SZ: usize = 32;
const MAX_ADDR_PER_BLOCK: usize = 30000;
const TYPE_TREE: u16 = 0;

type Address = [u8; 32];

pub trait Sink {
    fn send_chunk(&self, chunk: (Address, Vec<u8>)) -> Result<(), std::io::Error>;
}

pub trait Store {
    fn get_chunk(&self, addr: Address) -> Result<&[u8], std::io::Error>;
}

pub struct TreeWriter<'a> {
    sink: &'a mut Sink,
    tree_blocks: Vec<Vec<u8>>,
}

fn u16_be_bytes(v: u16) -> (u8, u8) {
    ((((v & 0xff00) >> 8) as u8), (v & 0xff) as u8)
}

impl<'a> TreeWriter<'a> {
    pub fn new(sink: &'a mut Sink) -> TreeWriter<'a> {
        TreeWriter {
            sink,
            tree_blocks: Vec::new(),
        }
    }

    fn take_and_clear_level(&mut self, level: usize) -> Vec<u8> {
        let mut block = Vec::new();
        std::mem::swap(&mut block, &mut self.tree_blocks[level]);
        block
    }

    fn add_addr(&mut self, level: usize, addr: Address) -> Result<(), std::io::Error> {
        if level > 0xffff {
            // Return proper error.
            panic!("tree overflow");
        }

        if self.tree_blocks.len() < level + 1 {
            self.tree_blocks.push(Vec::new());
        }

        if self.tree_blocks[level].len() == 0 {
            let (type_hi, type_lo) = u16_be_bytes(TYPE_TREE);
            let (height_hi, height_lo) = u16_be_bytes(level as u16);
            self.tree_blocks[level].extend(&[type_hi, type_lo, height_hi, height_lo]);
        }

        self.tree_blocks[level].extend(&addr);

        const MAX_SIZE: usize = HDR_SZ + (ADDRESS_SZ * MAX_ADDR_PER_BLOCK);
        if self.tree_blocks[level].len() == MAX_SIZE {
            let current_level_block = self.take_and_clear_level(level);
            let current_block_address: Address = [0; 32]; // XXX calculate address
            self.sink
                .send_chunk((current_block_address, current_level_block))?;
            self.add_addr(level + 1, current_block_address)?;
        }

        assert!(self.tree_blocks[level].len() < MAX_SIZE);

        Ok(())
    }

    pub fn add(&mut self, chunk: (Address, Vec<u8>)) -> Result<(), std::io::Error> {
        let addr = chunk.0;
        self.sink.send_chunk(chunk)?;
        self.add_addr(0, addr)?;
        Ok(())
    }

    fn finish_level(&mut self, level: usize) -> Result<Option<Address>, std::io::Error> {
        if self.tree_blocks.len() <= level {
            return Ok(None);
        }

        if self.tree_blocks[level].len() == 3 {
            // Empty block, skip it.
            return self.finish_level(level + 1);
        }

        // The tree block contains whole addresses.
        assert!(((self.tree_blocks[level].len() - HDR_SZ) % ADDRESS_SZ) == 0);

        if self.tree_blocks[level].len() == HDR_SZ + ADDRESS_SZ {
            let mut result_addr: Address = [0; 32];
            result_addr.clone_from_slice(&self.tree_blocks[level][HDR_SZ..]);
            return Ok(Some(result_addr));
        }

        // New addr = sha256
        let block = self.take_and_clear_level(level);
        let current_block_address: Address = [0; 32]; // XXX calculate address
        self.sink.send_chunk((current_block_address, block))?;
        match self.finish_level(level + 1)? {
            Some(addr) => Ok(Some(addr)),
            None => Ok(Some(current_block_address)),
        }
    }

    pub fn finish(mut self) -> Result<Address, std::io::Error> {
        Ok(self.finish_level(0)?.unwrap())
    }
}
