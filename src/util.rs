use anyhow::{anyhow, Context, Result};
use dirs::config_dir;
use std::ops::Shr;
use std::path::{Path, PathBuf};

/// Extract the AWS region from an IoT endpoint hostname
pub fn region_from_endpoint(endpoint: &str) -> Option<String> {
    // Expected formats:
    //  - <id>-ats.iot.<region>.amazonaws.com
    //  - <id>.iot.<region>.amazonaws.com
    let parts: Vec<&str> = endpoint.split('.').collect();
    // Find the "iot" label and take the next part as region
    if let Some(iot_idx) = parts.iter().position(|p| *p == "iot") {
        if let Some(region_part) = parts.get(iot_idx + 1) {
            return Some((*region_part).to_string());
        }
    }
    None
}

pub fn config_home(config_dir_opt: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = config_dir_opt {
        return Ok(p.clone());
    }
    let base = config_dir().ok_or_else(|| anyhow!("Could not resolve user config directory"))?;
    Ok(base.join("reclaim"))
}

pub fn hex_id_from_decimal(decimal: &str) -> Result<String> {
    if !crate::reclaim::validate_unique_id(decimal) {
        return Err(anyhow!("Invalid unique_id: must be 17 digits with valid checksum"));
    }
    let id_num: u64 = decimal.parse().context("parsing unique_id")?;
    Ok(format!("{:012x}", id_num.shr(8)))
}
