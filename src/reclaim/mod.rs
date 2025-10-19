use std::str::FromStr;
use json::JsonValue;

pub const DEFAULT_AWS_REGION: &str = "ap-southeast-2";
pub const DEFAULT_AWS_IDENTITY_POOL: &str = "ap-southeast-2:e04c5d62-0c40-4eac-a343-27d5f76c4920";
pub const DEFAULT_AWS_ENDPOINT: &str = "a254daig9zo2wn-ats.iot.ap-southeast-2.amazonaws.com";

#[derive(Debug, Clone)]
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

        let mut state = ReclaimState {
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
        };

        let values = match json {
            JsonValue::Object(obj) =>  {
                match obj.get("modbusVal") {
                    Some(JsonValue::Array(arr)) => arr.iter().map(|v| v.as_i64().unwrap_or(0)).collect::<Vec<i64>>(),
                    _ => vec![]
                }
            },
            _ => vec![]
        };

        for v in values.chunks(2) {
            match v[0] {
                50 => state.case_temperature = v[1] as f32 / 2.0,
                79 => state.water_temperature = v[1] as f32 / 2.0,
                200 => state.pump_active = v[1] != 0,
                213 => state.outlet_temperature = v[1] as f32,
                214 => state.inlet_temperature = v[1] as f32,
                215 => state.discharge_temperature = v[1] as f32,
                216 => state.suction = v[1] as f32,
                217 => state.evaporator = v[1] as f32,
                218 => state.ambient_temperature = v[1] as f32,
                219 => state.compressor_speed = v[1] as f32,
                220 => state.water_speed = v[1] as f32,
                221 => state.fan_speed = v[1] as f32,
                225 => state.power = v[1] as f32,
                226 => state.current = v[1] as f32,
                _ => {}
            }
        }

        Ok(state)
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

    #[test]
    fn test_from_str() {
        let str = r#"{"messageId":"read","modbusReg":1,"modbusVal":[16,53409,17,256,18,260,19,256,48,0,49,0,50,57,51,9,64,117,77,0,78,0,79,118,83,0,148,32771,149,65485,150,1536,151,44978,152,35295,153,128,154,0,200,0,201,0,202,0,203,32381,204,32381,205,32381,206,32381,207,32381,208,32381,209,32381,210,32381,211,0,213,54,214,54,215,71,216,30,217,22,218,25,219,0,220,0,221,0,222,17,223,9,224,0,225,0,226,0,233,27,240,0,241,65535,242,0,243,255,244,255,245,0,246,6144,40960,1,40961,0,40962,74,40963,118,40964,6,40965,5632,40966,2304,40967,0,40968,1536,40969,2560,40970,1536,40971,0,40972,1536,40973,2816,40974,768,40975,90,40976,0,40977,1536,40978,90,40979,120,40980,2560,40981,1536,40982,768,40983,21,40984,0,40985,0,40986,250,40987,10,40988,1,40989,0,40990,0,40991,2816,40992,768,40993,5,40994,1,40995,100,40996,1,40997,23,40998,0,40999,0,41000,1,41001,3072,41002,1536,41003,74,41004,118,41005,2560,41006,1536,41007,0,41008,0,41009,0,41010,4,41011,3,41012,90,41013,3000,41500,118,41501,118,41502,255,41503,255,41504,1,41505,255,41506,255,65283,1,65284,1,65285,15,65289,65535,65296,2025,65297,10,65298,19,65299,15,65300,38,65301,65535,65302,0,65303,6,65304,0,65305,35,65306,1,65316,15,65487,65535,65488,21061,65489,17228,65490,16713,65491,19798,65492,12800,65493,0,65494,0,65495,0]}"#;

        let state = ReclaimState::from_str(str).unwrap();
        assert_eq!(state.case_temperature, 28.5);
        assert_eq!(state.water_temperature, 59.0);
        assert_eq!(state.pump_active, false);
        assert_eq!(state.outlet_temperature, 54.0);
        assert_eq!(state.inlet_temperature, 54.0);
        assert_eq!(state.discharge_temperature, 71.0);
        assert_eq!(state.suction, 30.0);
        assert_eq!(state.evaporator, 22.0);
        assert_eq!(state.ambient_temperature, 25.0);
    }

}