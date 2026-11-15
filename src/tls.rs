//! TLS provider for outgoing connections (rustls with ring, like lettre). reqwest is built without
//! a provider of its own, so that no second one (aws-lc-rs with C dependencies) ends up in the
//! static binary.

/// Installs ring as the process-wide default provider; calling it more than once is harmless.
pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
