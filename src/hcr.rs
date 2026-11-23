//! Núcleo independente de framing HCR.
//!
//! O APK analisado usa frames binários com cabeçalho de 62 bytes: opcode,
//! versão e comprimento big-endian no offset 58. Este módulo não contém o
//! binário oficial nem faz download de assets. Ele fica isolado até que a
//! autenticação/sessão do cliente seja validada com uma captura real do APK.

use std::io::{self, Error, ErrorKind};

pub const HEADER_LEN: usize = 62;
pub const MAX_PAYLOAD: usize = 262_140;
pub const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: u8,
    pub version: u8,
    pub header: [u8; HEADER_LEN],
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: u8, payload: Vec<u8>) -> io::Result<Self> {
        if !(1..=6).contains(&opcode) {
            return Err(Error::new(ErrorKind::InvalidInput, "opcode HCR inválido"));
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::new(ErrorKind::InvalidInput, "payload HCR excede o limite"));
        }
        let mut header = [0u8; HEADER_LEN];
        header[0] = opcode;
        header[1] = VERSION;
        header[58..62].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        Ok(Self { opcode, version: VERSION, header, payload })
    }

    pub fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn parse(header: [u8; HEADER_LEN], payload: Vec<u8>) -> io::Result<Self> {
        let opcode = header[0];
        let version = header[1];
        let declared = u32::from_be_bytes(header[58..62].try_into().unwrap()) as usize;
        if !(1..=6).contains(&opcode) {
            return Err(Error::new(ErrorKind::InvalidData, "opcode HCR inválido"));
        }
        if version != VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "versão HCR não suportada"));
        }
        if declared > MAX_PAYLOAD || declared != payload.len() {
            return Err(Error::new(ErrorKind::InvalidData, "tamanho de payload HCR inválido"));
        }
        Ok(Self { opcode, version, header, payload })
    }

    pub fn session_id(&self) -> &[u8] { &self.header[2..18] }
    pub fn sequence_bytes(&self) -> &[u8] { &self.header[18..26] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_header_and_payload() {
        let frame = Frame::new(2, b"ssh-data".to_vec()).unwrap();
        let bytes = frame.encoded();
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&bytes[..HEADER_LEN]);
        let parsed = Frame::parse(header, bytes[HEADER_LEN..].to_vec()).unwrap();
        assert_eq!(parsed, frame);
        assert_eq!(u32::from_be_bytes(header[58..62].try_into().unwrap()), 8);
    }

    #[test]
    fn rejects_truncated_or_oversized_payload() {
        let mut header = [0u8; HEADER_LEN];
        header[0] = 1;
        header[1] = 1;
        header[58..62].copy_from_slice(&3u32.to_be_bytes());
        assert!(Frame::parse(header, b"no".to_vec()).is_err());
        header[58..62].copy_from_slice(&((MAX_PAYLOAD + 1) as u32).to_be_bytes());
        assert!(Frame::parse(header, vec![0; MAX_PAYLOAD + 1]).is_err());
    }
}
