// Taken from Opcard-rs implementation
// https://github.com/Nitrokey/opcard-rs/blob/ef8ee3b20958cf605a8d93ee98d28e337da9770f/src/virt.rs

mod dispatch;

use trussed::{
    types::Bytes,
    virt::{self, Client, StoreConfig},
};

/// Client type using a dispatcher with the backends required
pub type VirtClient<'a> = Client<'a, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    #[allow(clippy::unwrap_used)]
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes")),
            dispatch::BACKENDS,
            f,
        )
    })
}

/// Run the backend with the extensions required
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    with_client(StoreConfig::ram(), client_id, f)
}
