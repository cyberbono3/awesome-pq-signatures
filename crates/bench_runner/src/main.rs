mod adapters;
mod app;
mod cli;
mod registry;
mod reporting;
mod types;

fn main() {
    if let Err(err) = app::run(std::env::args().skip(1)) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
