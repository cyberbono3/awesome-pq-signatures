use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::adapters::{
    build_ffi_adapter, build_pure_adapter, DilithiumAdapter, FalconAdapter,
    HssAdapter, LeansigAdapter, LmsAdapter, MayoAdapter, RunnerContext,
    SphincsPlusAdapter, XmssAdapter, XmssmtAdapter,
};
use crate::cli::CliConfig;
use crate::types::DsaBenchmark;

macro_rules! pure_spec {
    ($algorithm:literal, $param_set:literal, $adapter:ty) => {
        AdapterSpec {
            algorithm: $algorithm,
            param_set: $param_set,
            executable_name: None,
            backend: BackendKind::Pure,
            builder: build_pure_adapter::<$adapter>,
        }
    };
}

macro_rules! ffi_spec {
    ($algorithm:literal, $param_set:literal, $bin:literal) => {
        AdapterSpec {
            algorithm: $algorithm,
            param_set: $param_set,
            executable_name: Some($bin),
            backend: BackendKind::Ffi,
            builder: build_ffi_adapter,
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Pure,
    Ffi,
}

#[derive(Clone, Copy)]
pub struct AdapterSpec {
    pub algorithm: &'static str,
    pub param_set: &'static str,
    pub executable_name: Option<&'static str>,
    pub backend: BackendKind,
    pub builder:
        fn(&RunnerContext, &'static AdapterSpec) -> Box<dyn DsaBenchmark>,
}

pub static ADAPTER_SPECS: &[AdapterSpec] = &[
    pure_spec!("ML-DSA-65 (Dilithium)", "ML-DSA-65", DilithiumAdapter),
    pure_spec!("Falcon-512", "Falcon-512", FalconAdapter),
    pure_spec!(
        "SPHINCS+-SHAKE-128f",
        "SPHINCS+-SHAKE-128f-simple",
        SphincsPlusAdapter
    ),
    pure_spec!("MAYO-1", "MAYO-1", MayoAdapter),
    pure_spec!("LMS", "LMS-SHA256-M32-H5", LmsAdapter),
    pure_spec!("HSS", "HSS-SHA256-H5-W2-L1", HssAdapter),
    pure_spec!("XMSS", "XMSS-SHA2_10_256", XmssAdapter),
    pure_spec!("XMSS^MT", "XMSSMT-SHA2_20/2_256", XmssmtAdapter),
    pure_spec!("LeanSig", "Poseidon-L2^18-TS-w4", LeansigAdapter),
    ffi_spec!("SQISign", "SQISign-lvl1", "sqisign"),
    ffi_spec!("LESS", "LESS-252-45", "less"),
    ffi_spec!("CROSS", "CROSS-RSDPG-192-BAL", "cross"),
];

pub fn selected_specs(config: &CliConfig) -> Vec<&'static AdapterSpec> {
    ADAPTER_SPECS
        .iter()
        .filter(|spec| spec.matches(config))
        .collect()
}

pub fn instantiate_adapters(
    specs: &[&'static AdapterSpec],
    context: &RunnerContext,
) -> Vec<Box<dyn DsaBenchmark>> {
    specs
        .iter()
        .map(|spec| (spec.builder)(context, spec))
        .collect()
}

pub fn resolve_ffi_binaries(
    specs: &[&'static AdapterSpec],
) -> Result<HashMap<&'static str, PathBuf>, String> {
    let ffi_specs: Vec<_> = specs
        .iter()
        .copied()
        .filter(|spec| spec.backend == BackendKind::Ffi)
        .collect();

    if ffi_specs.is_empty() {
        return Ok(HashMap::new());
    }

    let workspace_root = workspace_root();
    let mut build = Command::new("cargo");
    build
        .current_dir(&workspace_root)
        .args(["build", "--release"]);
    for spec in &ffi_specs {
        build.args(["--bin", spec.executable_name()?]);
    }
    let status = build
        .status()
        .map_err(|err| format!("failed to build FFI binaries: {err}"))?;
    if !status.success() {
        return Err(format!("release build failed with status {status}"));
    }

    let mut binaries = HashMap::new();
    let target_dir = workspace_root.join("target").join("release");
    for spec in ffi_specs {
        let bin_name = spec.executable_name()?;
        let executable = target_dir
            .join(format!("{bin_name}{}", std::env::consts::EXE_SUFFIX));
        if !executable.exists() {
            return Err(format!(
                "expected executable not found: {}",
                executable.display()
            ));
        }
        binaries.insert(spec.algorithm, executable);
    }

    Ok(binaries)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bench_runner should live under crates/ in workspace")
        .to_path_buf()
}

impl AdapterSpec {
    fn matches(&self, config: &CliConfig) -> bool {
        (!config.skip_ffi || self.backend != BackendKind::Ffi)
            && self.matches_filter(self.algorithm, &config.only_filters)
            && self.matches_filter(self.param_set, &config.param_set_filters)
    }

    fn matches_filter(&self, value: &str, filters: &[String]) -> bool {
        filters.is_empty()
            || filters
                .iter()
                .any(|filter| value.to_ascii_lowercase().contains(filter))
    }

    fn executable_name(&self) -> Result<&'static str, String> {
        self.executable_name.ok_or_else(|| {
            format!(
                "missing executable name for ffi algorithm: {}",
                self.algorithm
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_specs_respect_filters() {
        let mut config = CliConfig::default();
        config.only_filters.push("xmss".to_string());
        config.param_set_filters.push("20/2".to_string());
        let specs = selected_specs(&config);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].algorithm, "XMSS^MT");
    }
}
