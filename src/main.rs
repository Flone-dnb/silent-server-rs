use std::io;
use std::io::*;

mod config_io;
mod global_params;
use config_io::*;

fn main() {
    println!("Silent Server v{} (rs).\n", env!("CARGO_PKG_VERSION"));
    println!("Type 'help' to see commands...\n");

    let server_config = ServerConfig::new();
    if server_config.is_none() {
        pause();
        panic!();
    }
    let mut server_config = server_config.unwrap();

    loop {
        print!(">");
        io::stdout().flush().ok().expect("could not flush stdout");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("unable to read user input");

        input.pop(); // pop '\n'

        if input == "help" {
            println!("available commands:");
            println!("config - show current server configuration");
            println!("config reset - resets the config to default settings");
            println!("config.port = *value* - change server port");
            println!("config.password = *string* - change server password");
            println!("exit - exit application");
        } else if input.contains("config") {
            if input == "config" {
                println!("{:#?}", server_config);
            } else if input == "config reset" {
                server_config = server_config.reset_config();
                server_config.save_config().unwrap();
            } else if input.contains("config.port = ") {
                let port_str: String = input
                    .chars()
                    .take(0)
                    .chain(input.chars().skip("config.port = ".chars().count()))
                    .collect();

                let port_u16 = port_str.parse::<u16>();
                if port_u16.is_err() {
                    println!(
                        "can't parse value (maximum value for port is {})",
                        std::u16::MAX
                    );
                } else {
                    server_config.server_port = port_u16.unwrap();
                    server_config.save_config().unwrap();
                }
            } else if input.contains("config.password = ") {
                let password_str: String = input
                    .chars()
                    .take(0)
                    .chain(input.chars().skip("config.password = ".chars().count()))
                    .collect();
                server_config.server_password = password_str;
                server_config.save_config().unwrap();
            } else {
                println!("command '{}' not found", input);
            }
        } else if input == "exit" {
            break;
        } else {
            println!("command '{}' not found", input);
        }

        println!("");
    }
}

pub fn pause() {
    use std::io::prelude::*;

    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press Enter to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}
