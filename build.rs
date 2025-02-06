use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Get the output directory from cargo
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // Copy the entire templates directory to the output directory
    let templates_dir = Path::new("src/templates");
    let dest_dir = Path::new(&out_dir).join("templates");
    
    // Create destination directory and copy recursively
    fs::create_dir_all(&dest_dir).unwrap();
    fs::remove_dir_all(&dest_dir).unwrap_or(());  // Clean up any existing files
    copy_dir_all(templates_dir, &dest_dir).unwrap();
    
    // Watch the entire templates directory for changes
    println!("cargo:rerun-if-changed=src/templates");
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
} 
