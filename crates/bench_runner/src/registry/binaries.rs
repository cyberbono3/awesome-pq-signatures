use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{AdapterSpec, BackendKind};

pub fn resolve_binary_executables(
    specs: &[&'static AdapterSpec],
) -> Result<HashMap<&'static str, PathBuf>, String> {
    let binary_specs: Vec<_> = specs
        .iter()
        .copied()
        .filter(|spec| spec.backend != BackendKind::Pure)
        .collect();

    if binary_specs.is_empty() {
        return Ok(HashMap::new());
    }

    let workspace_root = workspace_root();
    let mut build = Command::new("cargo");
    build
        .current_dir(&workspace_root)
        .args(["build", "--release"]);
    for spec in &binary_specs {
        build.args(["--bin", spec.executable_name()?]);
    }
    let status = build
        .status()
        .map_err(|err| format!("failed to build benchmark binaries: {err}"))?;
    if !status.success() {
        return Err(format!("release build failed with status {status}"));
    }

    let mut binaries = HashMap::new();
    let target_dir = workspace_root.join("target").join("release");
    for spec in binary_specs {
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
