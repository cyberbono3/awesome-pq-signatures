use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4NoOff;
use leansig_bench::run_and_print;

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║          LeanSig Benchmark                       ║");
    println!("║  Poseidon2-based XMSS with Target Sum Encoding  ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    run_and_print::<SIGTargetSumLifetime18W4NoOff>("LeanSig Poseidon - L 2^18 - Target Sum - w 4");
}
