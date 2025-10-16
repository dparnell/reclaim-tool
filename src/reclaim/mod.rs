pub const DEFAULT_AWS_REGION: &str = "ap-southeast-2";
pub const DEFAULT_AWS_IDENTITY_POOL: &str = "ap-southeast-2:e04c5d62-0c40-4eac-a343-27d5f76c4920";
pub const DEFAULT_AWS_ENDPOINT: &str = "a254daig9zo2wn-ats.iot.ap-southeast-2.amazonaws.com";

pub fn validate_unique_id(id: &str) -> bool {
    // id is a 17 characters long integer
    if id.len() != 17 || !id.chars().all(|c| c.is_numeric()) {
        return false;
    }

    // convert to hex string
    let id_num = match id.parse::<u64>() {
        Ok(num) => num,
        Err(_) => return false,
    };
    let hexstr = format!("{:014x}", id_num);

    // build the lookup table used by the checksum
    let mut lut = Vec::with_capacity(256);
    let key = 47u8;
    for x in 0..256 {
        let mut i = x as u8;
        for _y in 0..8 {
            let j = i & 128;
            i <<= 1;
            if j != 0 {
                i ^= key;
            }
        }
        lut.push(i & 255);
    }

    // calculate the checksum
    let mut cksum = 0u8;
    let hexstr_bytes = hexstr.as_bytes();
    for x in 0..(hexstr.len() - 2) {
        cksum = lut[(cksum ^ hexstr_bytes[x]) as usize];
    }

    // compare checksum with last 2 hex digits
    let expected_cksum = u8::from_str_radix(&hexstr[hexstr.len() - 2..], 16).unwrap_or(255);
    expected_cksum == cksum
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_valid_id() {
        // to run this test, set the environment variable RECLAIM_UNIQUE_ID to a valid id
        option_env!("RECLAIM_UNIQUE_ID").map(|id| {
            assert!(validate_unique_id(id));
        });
    }

    #[test]
    fn test_invalid_length() {
        assert!(!validate_unique_id("123456"));
        assert!(!validate_unique_id("123456789012345678"));
    }

    #[test]
    fn test_non_numeric() {
        assert!(!validate_unique_id("1234567890123456a"));
        assert!(!validate_unique_id("abcdefghijklmnopq"));
    }

    #[test]
    fn test_invalid_checksum() {
        assert!(!validate_unique_id("12345678901234568"));
    }

}