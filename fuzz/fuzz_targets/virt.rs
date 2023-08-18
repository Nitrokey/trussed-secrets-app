// Taken from Opcard-rs implementation
// https://github.com/Nitrokey/opcard-rs/blob/ef8ee3b20958cf605a8d93ee98d28e337da9770f/src/virt.rs

mod dispatch;

use trussed::{
    types::Bytes,
    virt::{self, Client, Ram, StoreProvider},
};

/// Client type using a dispatcher with the backends required
pub type VirtClient<S> = Client<S, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
    where
        F: FnOnce(VirtClient<S>) -> R,
        S: StoreProvider,
{
    #[allow(clippy::unwrap_used)]
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            dispatch::Dispatch::with_hw_key(Bytes::from_slice(b"some bytes").unwrap()),
            dispatch::BACKENDS,
            f,
        )
    })
}

/// Run the backend with the extensions required
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
    where
        F: FnOnce(VirtClient<Ram>) -> R,
{
    with_client(Ram::default(), client_id, f)
}
