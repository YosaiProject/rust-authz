extern crate serde_codegen;

use std::env;
use std::path::Path;


pub fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();

    let src = Path::new("src/json_types.rs.in");
    let dst = Path::new(&out_dir).join("json_types.rs");

    serde_codegen::expand(&src, &dst).unwrap();
}
