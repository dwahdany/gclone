//! Passes the target triple to the crate (`GCLONE_TARGET`), for `gclone --version`. The
//! compile-time auth URL (`GCLONE_DEFAULT_AUTH_URL`) is read by `option_env!` in `src/auth`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=GCLONE_TARGET={target}");
}
