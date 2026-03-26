use crate::adapters::{
    build_binary_adapter, build_pure_adapter, DilithiumAdapter, FalconAdapter,
    HssAdapter, LamportAdapter, LmsAdapter, MayoAdapter, RunnerContext,
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
            builder: build_binary_adapter,
        }
    };
}

macro_rules! subprocess_spec {
    ($algorithm:literal, $param_set:literal, $bin:literal) => {
        AdapterSpec {
            algorithm: $algorithm,
            param_set: $param_set,
            executable_name: Some($bin),
            backend: BackendKind::Subprocess,
            builder: build_binary_adapter,
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Pure,
    Ffi,
    Subprocess,
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
    pure_spec!("Lamport OTS", "Lamport-OTS-256", LamportAdapter),
    pure_spec!("LMS", "LMS-SHA256-M32-H5", LmsAdapter),
    pure_spec!("HSS", "HSS-SHA256-H5-W2-L1", HssAdapter),
    pure_spec!("XMSS", "XMSS-SHA2_10_256", XmssAdapter),
    pure_spec!("XMSS^MT", "XMSSMT-SHA2_20/2_256", XmssmtAdapter),
    subprocess_spec!("LeanSig", "Poseidon-L2^18-TS-w4", "leansig"),
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

impl AdapterSpec {
    pub fn executable_name(&self) -> Result<&'static str, String> {
        self.executable_name.ok_or_else(|| {
            format!(
                "missing executable name for ffi algorithm: {}",
                self.algorithm
            )
        })
    }

    fn matches(&self, config: &CliConfig) -> bool {
        (!config.skip_ffi || self.backend != BackendKind::Ffi)
            && (!config.skip_subprocess || self.backend == BackendKind::Pure)
            && self.matches_filter(self.algorithm, &config.only_filters)
            && self.matches_filter(self.param_set, &config.param_set_filters)
    }

    fn matches_filter(&self, value: &str, filters: &[String]) -> bool {
        filters.is_empty()
            || filters
                .iter()
                .any(|filter| value.to_ascii_lowercase().contains(filter))
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

    #[test]
    fn skip_ffi_keeps_non_ffi_subprocess_benchmarks() {
        let mut config = CliConfig::default();
        config.skip_ffi = true;
        config.only_filters.push("leansig".to_string());
        let specs = selected_specs(&config);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].backend, BackendKind::Subprocess);
    }

    #[test]
    fn skip_subprocess_removes_leansig() {
        let mut config = CliConfig::default();
        config.skip_subprocess = true;
        config.only_filters.push("leansig".to_string());
        let specs = selected_specs(&config);
        assert!(specs.is_empty());
    }
}
