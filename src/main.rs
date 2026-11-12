//! The `gclone` binary: `main` → `cli::run`.

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(gclone::cli::run());
    // Do not wait for blocking tasks that may still sit in a terminal read.
    runtime.shutdown_background();
    std::process::exit(code);
}
