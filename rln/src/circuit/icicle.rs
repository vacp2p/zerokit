// This crate is based on the code by Ingonyama. Its preimage can be found here:
// https://github.com/ingonyama-zk/icicle

use ark_relations::r1cs::SynthesisError;

use crate::error::ProtocolError;

mod convert;
mod msm;
pub(crate) mod proof;

/// Error wrapper for ICICLE operations
fn icicle_err(_msg: &str) -> ProtocolError {
    ProtocolError::Synthesis(SynthesisError::PolynomialDegreeTooLarge)
}

/// Initialize ICICLE runtime and select device
pub fn init_icicle() -> Result<(), ProtocolError> {
    // Try to load CUDA backend, fall back to CPU
    let _ = icicle_runtime::runtime::load_backend_from_env_or_default();

    // Get device - try CUDA first, then CPU
    let device = icicle_runtime::Device::new("CUDA", 0);
    let device_result = icicle_runtime::set_device(&device);

    // If CUDA fails, try CPU
    if device_result.is_err() {
        let cpu_device = icicle_runtime::Device::new("CPU", 0);
        icicle_runtime::set_device(&cpu_device).map_err(|_| icicle_err("No device available"))?;
    }

    Ok(())
}
