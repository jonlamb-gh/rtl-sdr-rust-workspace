// Most of this was inspired by and/or taken directly from https://github.com/bemasher/rtlamr

// TODO
// - add log trace/debug/info stuff
// - redo preamble bit/byte matching
// - the ProtocolParser trait
// - buffering techniques, get rid of the rotate_left's
// - add support for other data formats
//   - cu8 currently suppports: Complex 8-bit unsigned
//   - add cs16 Complex 16-bit signed for the BladeRF
// - add support for other protocols: scm+, idm, netidm, r900, r900bcd, etc

pub mod protocols;
use protocols::*;

/// Packet-specific radio configuration
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct PacketConfig {
    pub center_freq: usize,
    pub data_rate: usize,
    pub chip_length: usize,
    pub preamble_symbols: usize,
    pub packet_symbols: usize,
}

impl PacketConfig {
    pub fn sample_rate(&self) -> usize {
        self.data_rate * self.chip_length
    }

    pub fn symbol_length(&self) -> usize {
        self.chip_length << 1
    }

    pub fn preamble_length(&self) -> usize {
        self.preamble_symbols * self.symbol_length()
    }

    pub fn block_size(&self) -> usize {
        next_power_of_2(self.preamble_length())
    }

    pub fn input_size(&self) -> usize {
        self.block_size() << 1
    }
}

pub trait ProtocolParser {
    //type Frame;

    const PACKET_CONFIG: PacketConfig;
    const PREAMBLE_BYTES: &'static [u8];

    fn parse(bytes: &[u8]) -> Result<Scm, FrameError>;
}

pub struct ScmParser;

impl ProtocolParser for ScmParser {
    //type Frame = Scm;

    const PACKET_CONFIG: PacketConfig = PacketConfig {
        center_freq: 912_600_155,
        data_rate: 32_768,
        chip_length: 72,
        preamble_symbols: 21,
        packet_symbols: 96,
    };

    const PREAMBLE_BYTES: &'static [u8] = &ScmFrame::<&[u8]>::PREAMBLE_BYTES;

    fn parse(bytes: &[u8]) -> Result<Scm, FrameError> {
        Scm::from_bytes(bytes)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
struct Config {
    pkt: PacketConfig,
    sample_rate: usize,
    block_size: usize,
    block_size2: usize,
    symbol_length: usize,
    preamble_length: usize,
    packet_length: usize,
    buffer_length: usize,
}

impl Config {
    // TODO - use the trait for PREAMBLE_BYTES
    fn new(pkt: PacketConfig) -> Self {
        //assert_eq!(preamble_symbols, PREAMBLE_BYTES.len());

        let symbol_length = pkt.chip_length << 1;
        let packet_length = pkt.packet_symbols * symbol_length;
        let preamble_length = pkt.preamble_symbols * symbol_length;
        let block_size = next_power_of_2(preamble_length);

        Config {
            pkt,
            sample_rate: pkt.sample_rate(),
            block_size,
            block_size2: block_size << 1,
            symbol_length,
            preamble_length,
            packet_length,
            buffer_length: packet_length + block_size,
        }
    }
}

type RmsPowerMax = f64;
type RmsPowerMean = f64;

#[derive(Debug)]
pub struct Decoder<P> {
    parser: P,
    cfg: Config,
    packet_counter: usize,
    msg_counter: usize,
    signal: Vec<f64>,
    quantized: Vec<u8>,
    csum: Vec<f64>,
    pkt: Vec<u8>,
    packed: Vec<u8>,
    s_idx_a: Vec<usize>,
    s_idx_b: Vec<usize>,
    mag_lut: Vec<f64>,
    msg_buffer: Vec<Scm>,
}

impl<P: ProtocolParser> Decoder<P> {
    pub fn new(parser: P) -> Self {
        let cfg = Config::new(P::PACKET_CONFIG);

        let mut mag_lut = vec![0.0; 0x100];
        for (idx, mag_lut) in mag_lut.iter_mut().enumerate() {
            *mag_lut = (127.5 - (idx as f64)) / 127.5;
            *mag_lut *= *mag_lut;
        }

        Decoder {
            parser,
            cfg,
            packet_counter: 0,
            msg_counter: 0,
            signal: vec![0.0; cfg.block_size + cfg.symbol_length],
            quantized: vec![0; cfg.buffer_length],
            csum: vec![0.0; cfg.block_size + cfg.symbol_length + 1],
            pkt: vec![0; (cfg.pkt.packet_symbols + 7) >> 3],
            packed: vec![0; (cfg.block_size + cfg.preamble_length + 7) >> 3],
            s_idx_a: Vec::with_capacity(cfg.block_size),
            s_idx_b: Vec::with_capacity(cfg.block_size),
            mag_lut,
            msg_buffer: Vec::with_capacity(32),
        }
    }

    pub fn input_size(&self) -> usize {
        self.cfg.block_size2
    }

    // TODO - redo this
    pub fn last_rms_power(&self) -> (RmsPowerMax, RmsPowerMean) {
        let magnitudes = &self.signal[..self.cfg.block_size];
        let max = magnitudes.iter().cloned().fold(f64::NAN, f64::max);
        let mean = magnitudes.iter().sum::<f64>() / magnitudes.len() as f64;
        (max, mean)
    }

    pub fn decode(&mut self, input: &[u8]) -> &[Scm] {
        self.s_idx_a.clear();
        self.s_idx_b.clear();
        self.msg_buffer.clear();

        // TODO - error type
        assert_eq!(input.len(), self.input_size());

        // Shift buffers to append new block
        // use VecDeque/SliceDeque or some other buffering technique
        self.signal.rotate_left(self.cfg.block_size);
        self.quantized.rotate_left(self.cfg.block_size);

        // Compute the magnitude of the new block
        for (input, output) in input
            .chunks_exact(2)
            .zip(self.signal[self.cfg.symbol_length..].iter_mut())
        {
            *output = self.mag_lut[input[0] as usize] + self.mag_lut[input[1] as usize];
        }

        // Perform matched filter on new block
        let mut sum: f64 = 0.0;
        for (idx, v) in self.signal.iter().enumerate() {
            sum += *v;
            self.csum[idx + 1] = sum;
        }
        let output = &mut self.quantized[self.cfg.packet_length..];
        let lower = &self.csum[self.cfg.pkt.chip_length..];
        let upper = &self.csum[self.cfg.symbol_length..];
        for (idx, l) in lower[..output.len()].iter().enumerate() {
            let f = (*l - self.csum[idx]) - (upper[idx] - l);
            output[idx] = 1 - (f.to_bits() >> 63) as u8;
        }

        // scm protocol
        // 111110010101001100000
        // 1_1111_0010_1010_0110_0000 : 21 bits
        // 0x1F2A60
        // TODO - redo this technique
        let preamble_str = "111110010101001100000";
        let mut preamble_bytes: [u8; 21] = [0; 21];
        assert_eq!(preamble_str.chars().count(), preamble_bytes.len());
        for (idx, c) in preamble_str.chars().enumerate() {
            if c == '1' {
                preamble_bytes[idx] = 1;
            }
        }

        // Get a list of packets with valid preambles.
        self.search(&preamble_bytes);

        // For each of the indices the preamble exists at
        for q_idx in self.s_idx_a.iter() {
            // Check that we're still within the first sample block. We'll catch
            // the message on the next sample block otherwise
            if *q_idx > self.cfg.block_size {
                continue;
            }

            // Packet is 1 bit per byte, pack to 8-bits per byte
            for p_idx in 0..self.cfg.pkt.packet_symbols {
                self.pkt[p_idx >> 3] <<= 1;
                self.pkt[p_idx >> 3] |= self.quantized[*q_idx + (p_idx * self.cfg.symbol_length)];
            }

            // Store the packet in the seen map and append to the packet list
            if let Ok(msg) = P::parse(&self.pkt[..]) {
                if !self.msg_buffer.contains(&msg) {
                    self.msg_buffer.push(msg);
                }
            }
        }

        self.packet_counter = self.packet_counter.wrapping_add(1);
        self.msg_counter = self.msg_counter.wrapping_add(self.msg_buffer.len());

        &self.msg_buffer
    }

    // Preable in terms of bytes, each byte is 1|0 from the preamble bits
    fn search(&mut self, preamble: &[u8]) {
        let sym_len_byte = self.cfg.symbol_length >> 3;

        // Pack the bit-wise quantized signal into bytes
        for b_idx in 0..self.packed.len() {
            let mut b: u8 = 0;
            for q_bit in &self.quantized[b_idx << 3..(b_idx + 1) << 3] {
                b = (b << 1) | q_bit;
            }
            self.packed[b_idx] = b;
        }

        // For each bit in the preamble
        for (p_idx, p_bit) in preamble.iter().enumerate() {
            // For 0, mask is 0xFF, for 1, mask is 0x00
            let p_bit = (p_bit ^ 1) * 0xFF;
            let offset = p_idx * sym_len_byte;

            // If this is the first bit of the preamble
            if p_idx == 0 {
                // Truncate the list of possible indices
                self.s_idx_a.clear();

                // For each packed byte
                for (q_idx, b) in self.packed[..self.cfg.block_size >> 3].iter().enumerate() {
                    // If the byte contains any bits that match the current preamble bit
                    if *b != p_bit {
                        // Add the index to the list
                        self.s_idx_a.push(q_idx);
                    }
                }
            } else {
                // From the list of possible indices, eliminate any indices at which
                // the preamble does not exist for the current preamble bit
                self.s_idx_b.clear();
                Self::search_pass_byte(
                    p_bit,
                    &self.packed[offset..],
                    &self.s_idx_a[..],
                    &mut self.s_idx_b,
                );
                std::mem::swap(&mut self.s_idx_a, &mut self.s_idx_b);

                // If we've eliminated all possible indices, there is no preamble
                if self.s_idx_a.is_empty() {
                    return;
                }
            }
        }

        let sym_len = self.cfg.symbol_length;

        // Truncate index list B
        self.s_idx_b.clear();

        // For each index in list A
        for q_idx in self.s_idx_a.iter() {
            // For each bit in the current byte
            for idx in 0..8 {
                // Add the signal-based index to index list B
                self.s_idx_b.push((q_idx << 3) + idx);
            }
        }

        // Swap index lists A and B
        std::mem::swap(&mut self.s_idx_a, &mut self.s_idx_b);

        // Check which indices the preamble actually exists at
        for (p_idx, p_bit) in preamble.iter().enumerate() {
            let offset = p_idx * sym_len;
            let offset_quantized = &self.quantized[offset..offset + self.cfg.block_size];

            // Search the list of possible indices for indices at which the preamble actually exists
            self.s_idx_b.clear();
            Self::search_pass(
                *p_bit,
                offset_quantized,
                &self.s_idx_a[..],
                &mut self.s_idx_b,
            );
            std::mem::swap(&mut self.s_idx_a, &mut self.s_idx_b);

            // If at the current bit of the preamble, there are no indices left to
            // check, the preamble does not exist in the current sample block
            if self.s_idx_a.is_empty() {
                return;
            }
        }
    }

    fn search_pass_byte(p_bit: u8, sig: &[u8], a: &[usize], b: &mut Vec<usize>) {
        for q_idx in a.iter() {
            if sig[*q_idx] != p_bit {
                b.push(*q_idx);
            }
        }
    }

    fn search_pass(p_bit: u8, sig: &[u8], a: &[usize], b: &mut Vec<usize>) {
        for q_idx in a.iter() {
            if sig[*q_idx] == p_bit {
                b.push(*q_idx);
            }
        }
    }
}

fn next_power_of_2(value: usize) -> usize {
    1 << ((value as f64).log2().ceil() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_approx_eq::assert_approx_eq;
    use core::num::NonZeroU32;
    use proptest::prelude::*;

    // Test data from https://github.com/merbanan/rtl_433_tests
    static SCM_G001_BYTES: &'static [u8; 40960] =
        include_bytes!("../../test_data/scm/g001_912.6M_2.4M.cu8");
    static SCM_G002_BYTES: &'static [u8; 40960] =
        include_bytes!("../../test_data/scm/g002_912.6M_2.4M.cu8");

    #[test]
    fn scm_decode_g001() {
        let mut dec = Decoder::new(ScmParser);
        let mut msg_buf = Vec::new();
        assert!(SCM_G001_BYTES.len() % dec.input_size() == 0);
        for chunk in SCM_G001_BYTES.chunks_exact(dec.input_size()) {
            for msg in dec.decode(&chunk[..]).iter() {
                msg_buf.push(*msg);
            }
        }
        assert_eq!(
            msg_buf,
            vec![Scm {
                id: NonZeroU32::new(54585868).unwrap(),
                commodity_type: CommodityType::Electric(12),
                physical_tamper: 3,
                encoder_tamper: 0,
                consumption: 562456,
            }]
        );

        let (max, mean) = dec.last_rms_power();
        assert_approx_eq!(max, 0.4905497885428681);
        assert_approx_eq!(mean, 0.05152867887351018);
    }

    #[test]
    fn scm_decode_g002() {
        let mut dec = Decoder::new(ScmParser);
        let mut msg_buf = Vec::new();
        assert!(SCM_G002_BYTES.len() % dec.input_size() == 0);
        for chunk in SCM_G002_BYTES.chunks_exact(dec.input_size()) {
            for msg in dec.decode(&chunk[..]).iter() {
                msg_buf.push(*msg);
            }
        }
        assert_eq!(
            msg_buf,
            vec![Scm {
                id: NonZeroU32::new(56355785).unwrap(),
                commodity_type: CommodityType::Electric(12),
                physical_tamper: 2,
                encoder_tamper: 0,
                consumption: 727018,
            }]
        );
        let (max, mean) = dec.last_rms_power();
        assert_approx_eq!(max, 1.6846751249519416);
        assert_approx_eq!(mean, 0.5574681312475974);
    }

    proptest! {
        #[test]
        fn power_of_2(num in 0_usize..=(core::usize::MAX >> 1)) {
            let next_po2 = next_power_of_2(num);
            prop_assert!(next_po2 >= num);
            prop_assert!(next_po2 > 0);
            prop_assert_eq!(next_po2.count_ones(), 1);
            let mut n = next_po2;
            while n != 1 {
                prop_assert_eq!(n % 2, 0);
                prop_assert_eq!(n & 1, 0);
                n = n / 2;
            }
        }
    }
}
