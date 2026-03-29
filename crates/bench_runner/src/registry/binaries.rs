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

    let mut binaries = HashMap::new();
    let mut specs_to_build = Vec::new();
    for spec in binary_specs {
        if let Some(executable) = override_executable(spec)? {
            binaries.insert(spec.algorithm, executable);
        } else {
            specs_to_build.push(spec);
        }
    }

    if specs_to_build.is_empty() {
        return Ok(binaries);
    }

    let workspace_root = workspace_root();
    let mut build = Command::new("cargo");
    build
        .current_dir(&workspace_root)
        .args(["build", "--release"]);
    for spec in &specs_to_build {
        build.args(["--bin", spec.executable_name()?]);
    }
    let status = build
        .status()
        .map_err(|err| format!("failed to build benchmark binaries: {err}"))?;
    if !status.success() {
        return Err(format!("release build failed with status {status}"));
    }

    let target_dir = workspace_root.join("target").join("release");
    for spec in specs_to_build {
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

fn override_executable(spec: &AdapterSpec) -> Result<Option<PathBuf>, String> {
    let var_name = override_env_var_name(spec.executable_name()?);
    match std::env::var_os(&var_name) {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.exists() {
                return Err(format!(
                    "override executable from {var_name} does not exist: {}",
                    path.display()
                ));
            }
            Ok(Some(path))
        }
        None => Ok(None),
    }
}

fn override_env_var_name(executable_name: &str) -> String {
    format!(
        "BENCH_RUNNER_BIN_{}",
        executable_name
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    )
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bench_runner should live under crates/ in workspace")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::RunnerContext;
    use crate::registry::{AdapterSpec, BackendKind};
    use crate::types::DsaBenchmark;

    fn unsupported_builder(
        _context: &RunnerContext,
        _spec: &'static AdapterSpec,
    ) -> Box<dyn DsaBenchmark> {
        panic!("test should not instantiate adapters");
    }

    #[test]
    fn override_env_var_name_normalizes_binary_name() {
        assert_eq!(
            override_env_var_name("leansig"),
            "BENCH_RUNNER_BIN_LEANSIG"
        );
        assert_eq!(
            override_env_var_name("sphincs-plus"),
            "BENCH_RUNNER_BIN_SPHINCS_PLUS"
        );
    }

    #[test]
    fn override_executable_uses_env_var_when_present() {
        let spec = AdapterSpec {
            algorithm: "Mock",
            param_set: "Mock-1",
            executable_name: Some("mock-bin"),
            backend: BackendKind::Subprocess,
            builder: unsupported_builder,
        };
        let var_name = override_env_var_name("mock-bin");
        let path = std::env::temp_dir().join("bench_runner_mock_override");
        std::fs::write(&path, b"").expect("mock file should be created");

        unsafe { std::env::set_var(&var_name, &path) };
        let resolved =
            override_executable(&spec).expect("override lookup should succeed");
        unsafe { std::env::remove_var(&var_name) };

        assert_eq!(resolved, Some(path.clone()));
        let _ = std::fs::remove_file(path);
    }
}
