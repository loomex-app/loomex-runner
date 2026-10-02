use std::{env, path::Path};

fn main() {
    // Cargo's PROFILE is "debug" for profiles inheriting dev. OUT_DIR's
    // profile directory identifies the selected custom profile instead.
    let out = env::var("OUT_DIR").expect("Cargo supplies OUT_DIR");
    let profile = Path::new(&out)
        .ancestors()
        .nth(3)
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .expect("Cargo OUT_DIR includes its profile directory");
    let profile = if profile == "debug" { "dev" } else { profile };
    println!("cargo:rustc-env=LOOMEX_BUILD_PROFILE={profile}");
    println!(
        "cargo:rustc-env=LOOMEX_BUILD_OPT_LEVEL={}",
        env::var("OPT_LEVEL").expect("Cargo supplies OPT_LEVEL")
    );
}
