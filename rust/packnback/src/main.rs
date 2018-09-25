extern crate clap;

use clap::{App, AppSettings, Arg, SubCommand};

fn run() -> i32 {
    let app = App::new("packnback")
        .version("unreleased")
        .about("reliable, security conscious backups")
        .subcommand(
            SubCommand::with_name("new-write-key").about("Generate a write only key for a store."),
        ).subcommand(
            SubCommand::with_name("serve-admin")
                .setting(AppSettings::Hidden)
                .about("Serve the packnback store admin protocol over stdin/stdout.")
                .arg(
                    Arg::with_name("store")
                        .required(true)
                        .help("Path to store that will be administered."),
                ),
        ).subcommand(
            SubCommand::with_name("recv")
                .setting(AppSettings::Hidden)
                .about("Receive packnback encrypted over stdin/stdout.")
                .arg(
                    Arg::with_name("store")
                        .required(true)
                        .help("Path to store that will receive the data."),
                ),
        ).subcommand(SubCommand::with_name("init").about("Init a store and generate a master key."))
        .subcommand(SubCommand::with_name("put").about("Encrypt then store data in a store."));

    let matches = app.get_matches();

    if let Some(_matches) = matches.subcommand_matches("init") {
        println!("init");
    } else if let Some(_matches) = matches.subcommand_matches("serve-admin") {
        println!("serve-admin");
    } else if let Some(_matches) = matches.subcommand_matches("recv") {
        println!("recv");
    } else if let Some(_matches) = matches.subcommand_matches("new-write-key") {
        println!("new-write-key");
    } else {
        eprintln!("see --help for usage information.");
        return 1;
    }

    0
}

fn main() {
    // Done like this to allow drop's to run.
    std::process::exit(run());
}
