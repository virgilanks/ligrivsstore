//! Trames de la messagerie native : longueur du message sur 32 bits, dans
//! l'ordre des octets de la machine (petit-boutiste sous Windows, x86-64 et
//! ARM64), puis le message JSON en UTF-8.
//!
//! Chrome limite à 1 Mo les messages de l'application vers le navigateur ;
//! la même limite, 1 Mio, s'applique ici dans les deux sens, y compris sur le
//! canal nommé entre le relais et l'application.

use std::io::{self, Read, Write};

use crate::ProtocolError;

/// Taille maximale d'un message, en octets.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Lit une trame. `Ok(None)` si le flux se termine proprement avant une
/// nouvelle trame ; une erreur si elle est tronquée ou trop grande.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut length = [0u8; 4];
    let mut filled = 0;
    while filled < length.len() {
        let read = match reader.read(length.get_mut(filled..).unwrap_or_default()) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        filled += read;
    }
    let size = u32::from_le_bytes(length) as usize;
    if size > MAX_FRAME {
        return Err(ProtocolError::TooLarge(size));
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Écrit une trame, puis vide le tampon.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), ProtocolError> {
    if payload.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge(payload.len()));
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| ProtocolError::TooLarge(payload.len()))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_in_order() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, br#"{"a":1}"#).unwrap();
        write_frame(&mut buffer, b"").unwrap();
        assert_eq!(buffer.get(..4).unwrap(), 7u32.to_le_bytes());
        let mut reader = buffer.as_slice();
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), br#"{"a":1}"#);
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"");
        assert!(read_frame(&mut reader).unwrap().is_none(), "fin propre");
    }

    #[test]
    fn truncated_frames_are_errors() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"0123456789").unwrap();
        for cut in [1, 3, 5, 13] {
            let mut reader = buffer.get(..cut).unwrap();
            assert!(read_frame(&mut reader).is_err(), "coupée à {cut} octets");
        }
    }

    #[test]
    fn oversized_frames_are_refused_without_allocation() {
        let mut header = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        header.extend_from_slice(b"x");
        assert!(matches!(
            read_frame(&mut header.as_slice()),
            Err(ProtocolError::TooLarge(size)) if size == MAX_FRAME + 1
        ));
        // 4 Gio annoncés : refusé avant toute lecture.
        let huge = u32::MAX.to_le_bytes();
        assert!(matches!(
            read_frame(&mut huge.as_slice()),
            Err(ProtocolError::TooLarge(_))
        ));
        let big = vec![b'x'; MAX_FRAME + 1];
        assert!(matches!(
            write_frame(&mut Vec::new(), &big),
            Err(ProtocolError::TooLarge(_))
        ));
        // La limite elle-même passe.
        let limit = vec![b'x'; MAX_FRAME];
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &limit).unwrap();
        assert_eq!(
            read_frame(&mut buffer.as_slice()).unwrap().unwrap().len(),
            MAX_FRAME
        );
    }
}
