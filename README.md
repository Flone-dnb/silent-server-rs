# Silent

Silent Server is a cross-platform command-line tool for hosting Silent Server.

Must be used with the [Silent Client](https://github.com/Flone-dnb/silent-rs) application.

# How to use

```
options:
--start - starts the server on launch

type 'help' to see commands...
```

If you want to host the server under NAT, you need to forward UDP and TCP port 51337 (can be changed in the config).

# Build

Use `cargo build --release` (requires Rust nightly) to build the app.

# License

Please note, that starting from version **1.1.1** this project is licensed under the MIT license.

All versions prior to version **1.1.1** were licensed under the ZLib license.
