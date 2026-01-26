// This crate is based on the code by Ingonyama. Its preimage can be found here:
// https://github.com/ingonyama-zk/icicle

use icicle_runtime::{runtime, set_device, Device};

use crate::error::ProtocolError;

mod convert;
mod msm;
pub(crate) mod proof;

/// Initialize ICICLE runtime and select device
pub fn init_icicle() -> Result<(), ProtocolError> {
    // Try to load CUDA backend, fall back to CPU
    let _ = runtime::load_backend_from_env_or_default();

    let cuda = Device::new("CUDA", 0);

    if set_device(&cuda).is_err() {
        let cpu = Device::new("CPU", 0);
        set_device(&cpu)?;
    }

    Ok(())
}
