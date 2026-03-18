use std::path::Path;

fn main() {
    #[cfg(target_os = "macos")]
    {
        for path in ["/opt/homebrew/opt/gmp/lib", "/usr/local/opt/gmp/lib"] {
            if Path::new(path).exists() {
                println!("cargo:rustc-link-search=native={path}");
                break;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for path in [
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/usr/lib64",
            "/usr/lib",
        ] {
            if Path::new(path).join("libgmp.so").exists()
                || Path::new(path).join("libgmp.a").exists()
            {
                println!("cargo:rustc-link-search=native={path}");
                break;
            }
        }
    }

    println!("cargo:rustc-link-lib=gmp");
}
