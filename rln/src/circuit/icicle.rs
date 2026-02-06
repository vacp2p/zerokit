// This crate is based on the code by Ingonyama. Its preimage can be found here:
// https://github.com/ingonyama-zk/icicle

mod convert;
mod msm;
pub(crate) mod proof;

use icicle_runtime::Device;

use crate::error::ProtocolError;

/// Initialize the ICICLE backend for GPU acceleration.
///
/// This function attempts to load the Metal backend (for macOS) or CUDA backend (for Linux/Windows)
/// and set it as the active device. If no GPU backend is available, it falls back to the CPU backend.
pub fn init_icicle_backend() -> Result<String, ProtocolError> {
    let mut device_name = String::from("CPU");

    icicle_runtime::runtime::load_backend_from_env_or_default()?;

    let metal_device = Device::new("METAL", 0);
    if icicle_runtime::is_device_available(&metal_device) {
        icicle_runtime::set_device(&metal_device)?;
        device_name = String::from("METAL");
        return Ok(device_name);
    }

    let cuda_device = Device::new("CUDA", 0);
    if icicle_runtime::is_device_available(&cuda_device) {
        icicle_runtime::set_device(&cuda_device)?;
        device_name = String::from("CUDA");
        return Ok(device_name);
    }

    let cpu_device = Device::new("CPU", 0);
    icicle_runtime::set_device(&cpu_device)?;

    Ok(device_name)
}
