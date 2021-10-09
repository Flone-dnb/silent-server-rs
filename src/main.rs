#![feature(linked_list_remove)]

// Std.
use std::env;
use std::io;
use std::io::*;

// Custom.
mod config_io;
mod global_params;
mod services;
use global_params::*;
use services::net_service::NetService;

fn main() {
    println!("Silent Server v{} (rs).\n", env!("CARGO_PKG_VERSION"));
    println!("Type 'help' to see commands...\n");

    let mut net_service = NetService::new();

    let args: Vec<String> = env::args().collect();

    loop {
        io::stdout().flush().ok().expect("could not flush stdout");
        let mut input = String::new();

        if args.len() > 1 {
            if args[1] == "--start" {
                input = "start".to_string();
            }
        } else {
            io::stdin()
                .read_line(&mut input)
                .expect("unable to read user input");

            input.pop(); // pop '\n'
            if cfg!(windows) {
                input.pop(); // pop '\r'
            }
        }

        if input == "help" {
            println!("\noptions:");
            println!("--start - starts the server on launch");
            println!("\ncommands:");
            println!("start - starts the server with the current configuration");
            println!("config - show the current server configuration");
            println!("config reset - resets the config to default settings");
            println!("config.port = *value* - change server's port");
            println!("config.password = *string* - change server's password");
            println!("rooms clear - removes all rooms except for the 'Lobby' room");
            println!("rooms add *room name* - adds a room");
            println!("rooms remove *room name* - removes a room");
            println!("exit - exit the application");
        } else if input == "start" {
            net_service.start();
        } else if input.contains("config") {
            if input == "config" {
                println!("{:#?}", net_service.server_config);
            } else if input == "config reset" {
                net_service.server_config = net_service.server_config.reset_config();
                net_service.server_config.save_config().unwrap();
            } else if input.contains("config.port = ") {
                let port_str: String = input
                    .chars()
                    .take(0)
                    .chain(input.chars().skip("config.port = ".chars().count()))
                    .collect();

                let port_u16 = port_str.parse::<u16>();
                if let Ok(value) = port_u16 {
                    net_service.server_config.server_port = value;
                    net_service.server_config.save_config().unwrap();
                } else {
                    println!(
                        "can't parse value (maximum value for port is {})",
                        std::u16::MAX
                    );
                }
            } else if input.contains("config.password = ") {
                let password_str: String = input
                    .chars()
                    .take(0)
                    .chain(input.chars().skip("config.password = ".chars().count()))
                    .collect();
                if password_str.chars().count() > MAX_PASSWORD_SIZE {
                    println!(
                        "the password is too big (max length: {})",
                        MAX_PASSWORD_SIZE
                    );
                } else {
                    net_service.server_config.server_password = password_str;
                    net_service.server_config.save_config().unwrap();
                }
            } else {
                println!("command '{}' not found", input);
            }
        } else if input == "rooms clear" {
            net_service.server_config.clear_rooms();
            net_service.server_config.save_config().unwrap();
        } else if input.contains("rooms add ") {
            let room_str: String = input
                .chars()
                .take(0)
                .chain(input.chars().skip("rooms add ".chars().count()))
                .collect();
            if let Err(msg) = net_service.server_config.add_room(room_str) {
                println!("{}", msg);
            } else {
                net_service.server_config.save_config().unwrap();
            }
        } else if input.contains("rooms remove ") {
            let room_str: String = input
                .chars()
                .take(0)
                .chain(input.chars().skip("rooms remove ".chars().count()))
                .collect();
            if let Err(msg) = net_service.server_config.remove_room(room_str) {
                println!("{}", msg);
            } else {
                net_service.server_config.save_config().unwrap();
            }
        } else if input == "exit" {
            break;
        } else {
            println!("command '{}' not found", input);
        }

        println!();
    }
}
