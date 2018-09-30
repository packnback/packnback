extern crate asymcrypt;
extern crate atty;
extern crate clap;
extern crate packnback;

use atty::Stream;
use clap::{App, AppSettings, Arg, SubCommand};

fn quick_start() {
    eprintln!(
        "Quickstart:

Generate a decryption master key, and a key to write backups with.

$ packnback new-key -o master.key
$ packnback new-key -o backup.key

Initialize a local data store

$ packnback init -store ./backups -master-key ./master.key

Allow the backup key to add (but not read or delete) backups.

$ packnback authorize-key -store ./backups -key ./backup.key

Store some data in the store:

$ echo hello | packnback save -store ./backups -name \"backup\" -key ./backup.key

Use the master key to print the backup we just made to stdout

$ packnback get -store ./backups -name \"backup\" -master-key ./master.key

TODO
... Store directory snapshots


Tips:
  - only the store master key can read or decrypt backups, store it securely.
  - losing the master key means you lose your data.
  - non master keys cannot modify, read, or delete old backups in a store."
    );
}

fn run_new_key(args: &clap::ArgMatches) -> i32 {
    let mut stdout = std::io::stdout();
    let mut _output_f: Option<std::fs::File> = None;
    let output = args.value_of("output").unwrap();
    let output_w: &mut std::io::Write = if output == "-" {
        if atty::is(Stream::Stdout) {
            eprintln!("Refusing to write binary key data to an interactive terminal!\n");
            eprintln!("Hint: Pipe the key to a file like this\n");
            eprintln!("$ packnback key > secret-packnback.key\n");
            eprintln!("For extra security set a private umask:\n");
            eprintln!("$ umask 077\n");
            eprintln!("This ensures the key is only readable by your user.");
            return 1;
        }
        &mut stdout
    } else {
        // XXX TODO IMPORTANT permission bits
        match std::fs::File::create(output) {
            Ok(f) => _output_f = Some(f),
            Err(e) => {
                eprintln!("{}", e);
                return 1;
            }
        };
        if let Some(ref mut f) = _output_f {
            f
        } else {
            panic!();
        }
    };

    let k = asymcrypt::Key::new();
    match k.write(output_w) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    }
    match output_w.flush() {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    }

    0
}

fn run_init(args: &clap::ArgMatches) -> i32 {
    let store_path = args.value_of("store").unwrap();
    let master_key_path = args.value_of("master-key").unwrap();
    let k = match asymcrypt::Key::from_path(&std::path::Path::new(&master_key_path)) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };
    match packnback::store::PacknbackStore::init(&std::path::Path::new(&store_path), &k.pub_key()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };
    0
}

fn run() -> i32 {
    let app = App::new("packnback")
        .version("work-in-progress")
        .about("reliable, security conscious backups")
        .subcommand(
            SubCommand::with_name("new-key")
                .about("Generate a new key for encrypting and decrypting data.")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("PATH")
                        .help("Output path for key file, - for stdout.")
                        .takes_value(true),
                ),
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
        ).subcommand(
            SubCommand::with_name("init")
                .about("Init a store with a key as the master key")
                .arg(
                    Arg::with_name("store")
                        .short("s")
                        .long("store")
                        .value_name("PATH")
                        .help("Path to initialize")
                        .takes_value(true)
                        .required(true),
                ).arg(
                    Arg::with_name("master-key")
                        .long("master-key")
                        .value_name("PATH")
                        .help("Path to master key file.")
                        .takes_value(true)
                        .required(true),
                ),
        ).subcommand(SubCommand::with_name("put").about("Encrypt then store data in a store."));

    let matches = app.get_matches();

    if let Some(matches) = matches.subcommand_matches("init") {
        run_init(matches)
    } else if let Some(_matches) = matches.subcommand_matches("serve-admin") {
        println!("serve-admin");
        0
    } else if let Some(_matches) = matches.subcommand_matches("recv") {
        println!("recv");
        0
    } else if let Some(matches) = matches.subcommand_matches("new-key") {
        run_new_key(matches)
    } else {
        quick_start();
        eprintln!("");
        eprintln!("see --help for usage information.");
        return 1;
    }
}

fn main() {
    // Done like this to allow drop's to run.
    std::process::exit(run());
}
