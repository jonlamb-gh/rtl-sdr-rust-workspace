//! ERT standard consumption message
//!
//! https://en.wikipedia.org/wiki/Encoder_receiver_transmitter

use crate::protocols::{crc16, CommodityType, FrameError};
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use core::num::NonZeroU32;

/// ERT standard consumption message
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Scm {
    pub id: NonZeroU32,
    pub commodity_type: CommodityType,
    pub physical_tamper: u8,
    pub encoder_tamper: u8,
    pub consumption: u32,
}

impl Scm {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FrameError> {
        Scm::try_from(bytes)
    }
}

impl TryFrom<&[u8]> for Scm {
    type Error = FrameError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let f = ScmFrame::new(bytes)?;
        Ok(Scm {
            id: f.id()?,
            commodity_type: f.commodity_type(),
            physical_tamper: f.physical_tamper(),
            encoder_tamper: f.encoder_tamper(),
            consumption: f.consumption(),
        })
    }
}

/// ERT standard consumption message frame
#[derive(Debug, Clone)]
pub struct ScmFrame<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::protocols::field::*;

    pub const PREAMBLE: Field = 0..4;
    pub const PREAMBLE_SHIFT: usize = 11;
    pub const PREAMBLE_MASK: u32 = 0x1F_FFFF;

    pub const ID_MSB: usize = 2;
    pub const ID_MSB_MASK: u8 = 0x06;
    pub const ID_MSB_SHIFT: usize = 23;
    pub const ID_LSB: Field = 6..10;
    pub const ID_LSB_MASK: u32 = 0x00FF_FFFF;

    pub const ERT_TYPE: usize = 3;
    pub const ERT_TYPE_MASK: u8 = 0x0F;
    pub const ERT_TYPE_SHIFT: usize = 2;

    pub const PHYS_TAMPER: usize = 3;
    pub const PHYS_TAMPER_MASK: u8 = 0xC0;
    pub const PHYS_TAMPER_SHIFT: usize = 6;

    pub const ENC_TAMPER: usize = 3;
    pub const ENC_TAMPER_MASK: u8 = 0x03;

    pub const CONSUMPTION: Field = 3..7;
    pub const CONSUMPTION_MASK: u32 = 0x00FF_FFFF;

    pub const CRC: Field = 10..12;

    pub const REST: Rest = 12..;
}

impl<T: AsRef<[u8]>> ScmFrame<T> {
    /// 1 sync bit, 20 preamble bits
    /// 0b1_1111_0010_1010_0110_0000
    pub const PREAMBLE: u32 = 0x00_1F_2A_60;
    pub const PREAMBLE_BYTES: [u8; 21] = [
        1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0,
    ];

    pub fn new_unchecked(buffer: T) -> ScmFrame<T> {
        ScmFrame { buffer }
    }

    pub fn new(buffer: T) -> Result<ScmFrame<T>, FrameError> {
        let f = Self::new_unchecked(buffer);
        f.check_len()?;
        f.check_preamble()?;
        f.check_crc()?;
        Ok(f)
    }

    pub fn check_len(&self) -> Result<(), FrameError> {
        let len = self.buffer.as_ref().len();
        if len < field::REST.start {
            Err(FrameError::MissingBytes)
        } else {
            Ok(())
        }
    }

    pub fn check_preamble(&self) -> Result<(), FrameError> {
        let p = self.preamble();
        if p != Self::PREAMBLE {
            Err(FrameError::InvalidPreamble(p))
        } else {
            Ok(())
        }
    }

    pub fn check_crc(&self) -> Result<(), FrameError> {
        let crc = self.crc();
        let data = self.buffer.as_ref();
        let crc_remainder = crc16(&data[2..12], 0x6F63);
        if crc_remainder != 0 {
            Err(FrameError::InvalidPacketCrc(crc))
        } else {
            Ok(())
        }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn as_le_u128(&self) -> u128 {
        let d = self.buffer.as_ref();
        u128::from_le_bytes([
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], 0, 0, 0, 0,
        ])
    }

    #[inline]
    pub fn buffer_len() -> usize {
        field::REST.start
    }

    #[inline]
    pub fn preamble(&self) -> u32 {
        let data = self.buffer.as_ref();
        (BigEndian::read_u32(&data[field::PREAMBLE]) >> field::PREAMBLE_SHIFT)
            & field::PREAMBLE_MASK
    }

    #[inline]
    pub fn id(&self) -> Result<NonZeroU32, FrameError> {
        let data = self.buffer.as_ref();
        let msb = data[field::ID_MSB] & field::ID_MSB_MASK;
        let lsb = BigEndian::read_u32(&data[field::ID_LSB]) & field::ID_LSB_MASK;
        let raw_id = ((msb as u32) << field::ID_MSB_SHIFT) | lsb;
        if let Some(id) = NonZeroU32::new(raw_id) {
            Ok(id)
        } else {
            Err(FrameError::InvalidId(raw_id))
        }
    }

    #[inline]
    pub fn commodity_type(&self) -> CommodityType {
        let data = self.buffer.as_ref();
        let typ = (data[field::ERT_TYPE] >> field::ERT_TYPE_SHIFT) & field::ERT_TYPE_MASK;
        CommodityType::from(typ)
    }

    #[inline]
    pub fn physical_tamper(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::PHYS_TAMPER] & field::PHYS_TAMPER_MASK) >> field::PHYS_TAMPER_SHIFT
    }

    #[inline]
    pub fn encoder_tamper(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::ENC_TAMPER] & field::ENC_TAMPER_MASK
    }

    #[inline]
    pub fn consumption(&self) -> u32 {
        let data = self.buffer.as_ref();
        BigEndian::read_u32(&data[field::CONSUMPTION]) & field::CONSUMPTION_MASK
    }

    #[inline]
    pub fn crc(&self) -> u16 {
        let data = self.buffer.as_ref();
        BigEndian::read_u16(&data[field::CRC])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ScmFrame<T> {
    #[inline]
    pub fn set_crc(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        BigEndian::write_u16(&mut data[field::CRC], value);
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ScmFrame<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static FRAME_BYTES: [u8; 12] = [
        0xF9, 0x53, 0x0, 0xF0, 0x02, 0xB6, 0x3C, 0xC0, 0xB1, 0x36, 0x36, 0xA0,
    ];

    #[test]
    fn header_len() {
        assert_eq!(ScmFrame::<&[u8]>::buffer_len(), 12);
    }

    #[test]
    fn deconstruct() {
        let f = ScmFrame::new(&FRAME_BYTES[..]).unwrap();
        assert_eq!(f.preamble(), ScmFrame::<&[u8]>::PREAMBLE);
        assert_eq!(f.id().unwrap().get(), 12628278);
        assert_eq!(f.commodity_type(), CommodityType::Electric(12));
        assert_eq!(f.physical_tamper(), 3);
        assert_eq!(f.encoder_tamper(), 0);
        assert_eq!(f.consumption(), 177724);
        assert_eq!(f.crc(), 0x36A0);
        assert_eq!(f.as_le_u128(), 0xA03636B1C03CB602F00053F9);
    }

    #[test]
    fn missing_bytes() {
        let bytes = [0xFF; 12 - 1];
        assert_eq!(bytes.len(), ScmFrame::<&[u8]>::buffer_len() - 1);
        let f = ScmFrame::new(&bytes[..]);
        assert_eq!(f.unwrap_err(), FrameError::MissingBytes);
    }

    #[test]
    fn invalid_preamble() {
        let bytes = [0xFF; 12];
        let f = ScmFrame::new(&bytes[..]);
        assert_eq!(f.unwrap_err(), FrameError::InvalidPreamble(0x1F_FFFF));
    }

    /*
    #[test]
    fn invalid_id() {
        todo!();
    }
    */

    #[test]
    fn invalid_crc() {
        let mut bytes = FRAME_BYTES.clone();
        let mut f = ScmFrame::new(&mut bytes[..]).unwrap();
        f.set_crc(1234);
        let bytes = f.into_inner();
        let f = ScmFrame::new(&bytes[..]);
        assert_eq!(f.unwrap_err(), FrameError::InvalidPacketCrc(1234));
    }
}
