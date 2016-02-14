use std::io::{Read, Write, Error, ErrorKind};

pub fn read_varint_u64<T: Read>(r: &mut T) -> Result<u64, Error> {
    let mut buf = [0u8; 1];
    let mut value = 0;
    for i in 0..10 {
        try!(r.read_exact(&mut buf[..]));
        value |= ((buf[0] & 0b01111111) as u64) << (i * 7);
        if buf[0] & 0b10000000 == 0 {
            break;
        } else if i == 9 {
            return Err(Error::new(ErrorKind::InvalidData, "varint overflow"));
        }
    }
    Ok(value)
}

pub fn write_varint_u64<T: Write>(w: &mut T,
                                  value: u64)
                                  -> Result<usize, Error> {
    let mut value = value;
    let mut buf = [0; 1];
    let mut count = 0;
    while value >= 0b10000000 {
        buf[0] = (value | 0b10000000) as u8;
        try!(w.write_all(&buf[..]));
        count += 1;
        value = value >> 7;
    }

    buf[0] = (value & 0b01111111) as u8;
    try!(w.write_all(&buf[..]));
    Ok(count + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::{u8, u32, u64};

    #[test]
    fn test_write_read_varint_u64() {
        let mut buf = Cursor::new(Vec::new());

        assert!(write_varint_u64(&mut buf, 0).is_ok());
        assert!(write_varint_u64(&mut buf, 1).is_ok());
        assert!(write_varint_u64(&mut buf, 17).is_ok());
        assert!(write_varint_u64(&mut buf, 126).is_ok());
        assert!(write_varint_u64(&mut buf, 127).is_ok());
        assert!(write_varint_u64(&mut buf, u8::MAX as u64).is_ok());
        assert!(write_varint_u64(&mut buf, (u8::MAX as u64) + 1).is_ok());
        assert!(write_varint_u64(&mut buf, 1024).is_ok());
        assert!(write_varint_u64(&mut buf, u32::MAX as u64).is_ok());
        assert!(write_varint_u64(&mut buf, (u32::MAX as u64) + 1).is_ok());
        assert!(write_varint_u64(&mut buf, u64::MAX).is_ok());
        assert!(write_varint_u64(&mut buf, 0).is_ok());

        buf.set_position(0);

        assert_eq!(read_varint_u64(&mut buf).unwrap(), 0);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), 1);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), 17);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), 126);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), 127);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), u8::MAX as u64);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), (u8::MAX as u64) + 1);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), 1024);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), u32::MAX as u64);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), (u32::MAX as u64) + 1);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), u64::MAX);
        assert_eq!(read_varint_u64(&mut buf).unwrap(), 0);
    }

    #[test]
    fn test_detects_overflow() {
        let mut buf = Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(read_varint_u64(&mut buf).is_err());
    }
}
