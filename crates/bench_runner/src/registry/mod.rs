mod binaries;
mod specs;

pub use binaries::resolve_binary_executables;
pub use specs::{
    instantiate_adapters, selected_specs, AdapterSpec, BackendKind,
};
