use std::fmt;

pub const ADDRESS_SZ: usize = 32;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct Address {
    pub bytes: [u8; 32],
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_hex_addr())
    }
}

impl Address {
    pub fn from_bytes(bytes: &[u8; 32]) -> Address {
        Address { bytes: *bytes }
    }

    pub fn as_hex_addr(&self) -> HexAddress {
        let tab = b"0123456789abcdef";
        let mut result = HexAddress::default();
        for i in 0..self.bytes.len() {
            let b = self.bytes[i];
            let hi = (b & 0xf0) >> 4;
            let lo = b & 0x0f;
            result.bytes[2 * i] = tab[hi as usize];
            result.bytes[2 * i + 1] = tab[lo as usize];
        }
        result
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::from_bytes(&[0; 32])
    }
}

pub struct HexAddress {
    bytes: [u8; 64],
}

impl<'a> HexAddress {
    pub fn as_str(&'a self) -> &'a str {
        std::str::from_utf8(&self.bytes).unwrap()
    }
}

impl fmt::Display for HexAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", std::str::from_utf8(&self.bytes).unwrap())
    }
}

impl Default for HexAddress {
    fn default() -> HexAddress {
        HexAddress {
            bytes: ['0' as u8; 64],
        }
    }
}

#[test]
fn test_addr_to_hex_addr() {
    assert!(Address::default().as_hex_addr().bytes[..] == HexAddress::default().bytes[..]);
}
