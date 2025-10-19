use std::str::FromStr;

pub const DEFAULT_AWS_REGION: &str = "ap-southeast-2";
pub const DEFAULT_AWS_IDENTITY_POOL: &str = "ap-southeast-2:e04c5d62-0c40-4eac-a343-27d5f76c4920";
pub const DEFAULT_AWS_ENDPOINT: &str = "a254daig9zo2wn-ats.iot.ap-southeast-2.amazonaws.com";

pub struct ReclaimState {
    pub pump_active: bool,
    pub case_temperature: f32,
    pub water_temperature: f32,
    pub outlet_temperature: f32,
    pub inlet_temperature: f32,
    pub discharge_temperature: f32,
    pub suction: f32,
    pub evaporator: f32,
    pub ambient_temperature: f32,
    pub compressor_speed: f32,
    pub water_speed: f32,
    pub fan_speed: f32,
    pub power: f32,
    pub current: f32,
}

impl FromStr for ReclaimState {
    type Err = json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = json::parse(s)?;

        Ok(ReclaimState {
            pump_active: false,
            case_temperature: 0.0,
            water_temperature: 0.0,
            outlet_temperature: 0.0,
            inlet_temperature: 0.0,
            discharge_temperature: 0.0,
            suction: 0.0,
            evaporator: 0.0,
            ambient_temperature: 0.0,
            compressor_speed: 0.0,
            water_speed: 0.0,
            fan_speed: 0.0,
            power: 0.0,
            current: 0.0,
        })
    }
}

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