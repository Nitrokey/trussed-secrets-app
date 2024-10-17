use trussed::{
    api::{reply, request, Reply, Request},
    backend::{Backend as _, BackendId},
    error::Error,
    platform::Platform,
    serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl as _},
    service::ServiceResources,
    types::{Bytes, Context, Location},
};
use trussed_auth::{AuthBackend, AuthContext, AuthExtension, MAX_HW_KEY_LEN};

pub const BACKENDS: &[BackendId<Backend>] = &[BackendId::Custom(Backend::Auth), BackendId::Core];

pub enum Backend {
    Auth,
}

pub enum Extension {
    Auth,
}

impl From<Extension> for u8 {
    fn from(extension: Extension) -> Self {
        match extension {
            Extension::Auth => 0,
        }
    }
}

impl TryFrom<u8> for Extension {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        match id {
            0 => Ok(Extension::Auth),
            _ => Err(Error::InternalError),
        }
    }
}

pub struct Dispatch {
    auth: AuthBackend,
}

#[derive(Default)]
pub struct DispatchContext {
    auth: AuthContext,
}

impl Dispatch {
    pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
        Self {
            auth: AuthBackend::with_hw_key(Location::Internal, hw_key),
        }
    }
}

impl ExtensionDispatch for Dispatch {
    type BackendId = Backend;
    type Context = DispatchContext;
    type ExtensionId = Extension;

    fn core_request<P: Platform>(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        match backend {
            Backend::Auth => {
                self.auth
                    .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
            }
        }
    }

    fn extension_request<P: Platform>(
        &mut self,
        backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut Context<Self::Context>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        match backend {
            Backend::Auth => match extension {
                Extension::Auth => self.auth.extension_request_serialized(
                    &mut ctx.core,
                    &mut ctx.backends.auth,
                    request,
                    resources,
                ),
            },
        }
    }
}

impl ExtensionId<AuthExtension> for Dispatch {
    type Id = Extension;

    const ID: Self::Id = Self::Id::Auth;
}
