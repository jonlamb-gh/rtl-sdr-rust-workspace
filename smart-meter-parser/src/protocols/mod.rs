mod scm;
pub use scm::{Scm, ScmFrame};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum FrameError {
    MissingBytes,
    InvalidPreamble(u32),
    InvalidId(u32),
    InvalidPacketCrc(u16),
    InvalidMeterIdCrc(u16),
}

// TODO - https://github.com/bemasher/rtlamr/pull/142
// seems like they also are getting type 12 for some electric meters like I am
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum CommodityType {
    /// Electric: 04, 05, 07, 08, 12
    Electric(u8),
    /// Gas: 02, 09
    Gas(u8),
    /// Water: 11, 13
    Water(u8),
    Unknown(u8),
}

impl From<u8> for CommodityType {
    fn from(typ: u8) -> Self {
        match typ {
            4 | 5 | 7 | 8 | 12 => CommodityType::Electric(typ),
            2 | 9 => CommodityType::Gas(typ),
            11 | 13 => CommodityType::Water(typ),
            _ => CommodityType::Unknown(typ),
        }
    }
}

impl From<CommodityType> for u8 {
    fn from(c: CommodityType) -> Self {
        match c {
            CommodityType::Electric(v) => v,
            CommodityType::Gas(v) => v,
            CommodityType::Water(v) => v,
            CommodityType::Unknown(v) => v,
        }
    }
}

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub fn crc16(bytes: &[u8], polynomial: u16) -> u16 {
    let mut remainder: u16 = 0;
    for b in bytes.iter() {
        remainder ^= (*b as u16) << 8;
        for _bit in 0..8 {
            if remainder & 0x8000 != 0 {
                remainder = (remainder << 1) ^ polynomial;
            } else {
                remainder <<= 1;
            }
        }
    }
    remainder
}
