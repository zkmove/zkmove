// Copyright (c) zkMove Authors

use env_logger::{Builder, Env};
pub use log::{debug, error, info, log_enabled, warn, Level};

pub mod prelude {
    pub use log::{debug, error, info, log_enabled, warn, Level};
}

pub fn init() {
    let _ = env_logger::builder().try_init();
}

pub fn init_for_test() {
    let _ = Builder::from_env(Env::default().default_filter_or("debug")).try_init();
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn test_log() {
        super::init_for_test();
        info!("This record will be captured by `cargo test`");
        debug!("This record will be captured by `cargo test`");
        warn!("This record will be captured by `cargo test`");

        assert_eq!(2, 1 + 1);
    }
}
