use leansig_bench::{run_and_print, LEANSIG_VARIANT, SelectedLeanSigScheme};

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║          LeanSig Benchmark                       ║");
    println!("║  Poseidon2-based XMSS with Target Sum Encoding  ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    run_and_print::<SelectedLeanSigScheme>(LEANSIG_VARIANT);
}
