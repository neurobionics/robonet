use clap::Parser;

#[derive(Parser)]
struct Cli {
    pattern: String,
    path: std::path::PathBuf,
}

fn main() {
    let args: Cli = Cli::parse();
    println!("Runnnig with pattern: {:?}, path: {:?}", args.pattern, args.path);

    let contents = std::fs::read_to_string(args.path).expect("Could not read file");

    for line in contents.lines() {
        if line.contains(&args.pattern) {
            println!("{}", line);
        }
    }

}
