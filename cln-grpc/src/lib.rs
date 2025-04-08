// Huge json!() macros require lots of recursion
#![recursion_limit = "1024"]

pub mod pb;

cfg_if::cfg_if! {
    if #[cfg(feature = "server")] {
        mod convert;
        mod server;
        pub use server::Server;
    }
}

#[cfg(test)]
mod test;
