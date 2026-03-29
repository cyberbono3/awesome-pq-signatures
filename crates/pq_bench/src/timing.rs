use std::{
    env,
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkOperation {
    Keygen,
    Sign,
    Verify,
}

impl FromStr for BenchmarkOperation {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "keygen" => Ok(Self::Keygen),
            "sign" => Ok(Self::Sign),
            "verify" => Ok(Self::Verify),
            other => Err(format!(
                "unsupported OPERATION={other}; expected one of: keygen, sign, verify"
            )),
        }
    }
}

pub fn measure_time<T, F>(operation: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

pub fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    let n = values.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2
    }
}

pub fn format_ns(ns: u128) -> String {
    format!("{:.3}ms", ns as f64 / 1e6)
}

pub fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

pub fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

pub fn run_with_large_stack(
    name: &str,
    stack_size: usize,
    operation: impl FnOnce() + Send + 'static,
) {
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(stack_size)
        .spawn(operation)
        .expect("thread should start")
        .join()
        .expect("thread should complete");
}

pub fn parse_usize_env(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}

pub fn parse_bool_env(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => {
            matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
        }
        Err(_) => default,
    }
}
