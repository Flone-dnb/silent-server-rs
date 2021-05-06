#![feature(linked_list_remove)]

use std::io;
use std::io::*;

mod config_io;
mod global_params;
mod services;
use services::net_service::NetService;

fn main() {
    println!("Silent Server v{} (rs).\n", env!("CARGO_PKG_VERSION"));
    println!("Type 'help' to see commands...\n");

    let mut net_service = NetService::new();

    loop {
        io::stdout().flush().ok().expect("could not flush stdout");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("unable to read user input");

        input.pop(); // pop '\n'

        if input == "help" {
            println!("available commands:");
            println!("start - starts the server with the current configuration");
            println!("config - show the current server configuration");
            println!("config reset - resets the config to default settings");
            println!("config.port = *value* - change server's port");
            println!("config.password = *string* - change server's password");
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
                if port_u16.is_err() {
                    println!(
                        "can't parse value (maximum value for port is {})",
                        std::u16::MAX
                    );
                } else {
                    net_service.server_config.server_port = port_u16.unwrap();
                    net_service.server_config.save_config().unwrap();
                }
            } else if input.contains("config.password = ") {
                let password_str: String = input
                    .chars()
                    .take(0)
                    .chain(input.chars().skip("config.password = ".chars().count()))
                    .collect();
                net_service.server_config.server_password = password_str;
                net_service.server_config.save_config().unwrap();
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
