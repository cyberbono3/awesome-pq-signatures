use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::adapters::{
    build_dilithium, build_falcon, build_ffi_adapter, build_hss, build_leansig,
    build_lms, build_mayo, build_sphincs_plus, build_xmss, build_xmssmt,
    RunnerContext,
};
use crate::cli::CliConfig;
use crate::types::DsaBenchmark;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Pure,
    Ffi,
}

#[derive(Clone, Copy)]
pub struct AdapterSpec {
    pub algorithm: &'static str,
    pub param_set: &'static str,
    pub backend: BackendKind,
    pub builder:
        fn(&RunnerContext, &'static AdapterSpec) -> Box<dyn DsaBenchmark>,
}

pub static ADAPTER_SPECS: &[AdapterSpec] = &[
    AdapterSpec {
        algorithm: "ML-DSA-65 (Dilithium)",
        param_set: "ML-DSA-65",
        backend: BackendKind::Pure,
        builder: build_dilithium,
    },
    AdapterSpec {
        algorithm: "Falcon-512",
        param_set: "Falcon-512",
        backend: BackendKind::Pure,
        builder: build_falcon,
    },
    AdapterSpec {
        algorithm: "SPHINCS+-SHAKE-128f",
        param_set: "SPHINCS+-SHAKE-128f-simple",
        backend: BackendKind::Pure,
        builder: build_sphincs_plus,
    },
    AdapterSpec {
        algorithm: "MAYO-1",
        param_set: "MAYO-1",
        backend: BackendKind::Pure,
        builder: build_mayo,
    },
    AdapterSpec {
        algorithm: "LMS",
        param_set: "LMS-SHA256-M32-H5",
        backend: BackendKind::Pure,
        builder: build_lms,
    },
    AdapterSpec {
        algorithm: "HSS",
        param_set: "HSS-SHA256-H5-W2-L1",
        backend: BackendKind::Pure,
        builder: build_hss,
    },
    AdapterSpec {
        algorithm: "XMSS",
        param_set: "XMSS-SHA2_10_256",
        backend: BackendKind::Pure,
        builder: build_xmss,
    },
    AdapterSpec {
        algorithm: "XMSS^MT",
        param_set: "XMSSMT-SHA2_20/2_256",
        backend: BackendKind::Pure,
        builder: build_xmssmt,
    },
    AdapterSpec {
        algorithm: "LeanSig",
        param_set: "Poseidon-L2^18-TS-w4",
        backend: BackendKind::Pure,
        builder: build_leansig,
    },
    AdapterSpec {
        algorithm: "SQISign",
        param_set: "SQISign-lvl1",
        backend: BackendKind::Ffi,
        builder: build_ffi_adapter,
    },
    AdapterSpec {
        algorithm: "LESS",
        param_set: "LESS-252-45",
        backend: BackendKind::Ffi,
        builder: build_ffi_adapter,
    },
    AdapterSpec {
        algorithm: "CROSS",
        param_set: "CROSS-RSDPG-192-BAL",
        backend: BackendKind::Ffi,
        builder: build_ffi_adapter,
    },
];

pub fn selected_specs(config: &CliConfig) -> Vec<&'static AdapterSpec> {
    ADAPTER_SPECS
        .iter()
        .filter(|spec| {
            (!config.skip_ffi || spec.backend != BackendKind::Ffi)
                && matches_filter(spec.algorithm, &config.only_filters)
                && matches_filter(spec.param_set, &config.param_set_filters)
        })
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
        build.args(["--bin", ffi_bin_name(spec.algorithm)?]);
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
        let bin_name = ffi_bin_name(spec.algorithm)?;
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

fn matches_filter(value: &str, filters: &[String]) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| value.to_ascii_lowercase().contains(filter))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bench_runner should live under crates/ in workspace")
        .to_path_buf()
}

fn ffi_bin_name(algorithm: &str) -> Result<&'static str, String> {
    match algorithm {
        "SQISign" => Ok("sqisign"),
        "LESS" => Ok("less"),
        "CROSS" => Ok("cross"),
        _ => Err(format!("unknown ffi algorithm: {algorithm}")),
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
