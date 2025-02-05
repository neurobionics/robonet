use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Get the output directory from cargo
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // Create services directory if it doesn't exist
    let services_dir = Path::new(&out_dir).join("services");
    fs::create_dir_all(&services_dir).unwrap();
    
    // Copy the service template
    println!("cargo:rerun-if-changed=src/services/rpi-connectivity-manager.service");
} 
