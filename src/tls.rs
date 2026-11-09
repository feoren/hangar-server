//! TLS-Anbieter für ausgehende Verbindungen (rustls mit ring, wie lettre). reqwest wird ohne
//! eigenen Anbieter gebaut, damit kein zweiter (aws-lc-rs mit C-Abhängigkeiten) im statischen
//! Binary landet.

/// Setzt ring als Standard-Anbieter des Prozesses; mehrfacher Aufruf schadet nicht.
pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
