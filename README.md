# Security Demo Application

This Android application demonstrates various security features and cryptographic operations. It
showcases:

* **Cryptographic Operations:**
    * Text signing and verification using different algorithms (RSA, ECDSA) and digest sizes.
    * Simple JSON Web Token (JWT) creation and verification.
    * Display of public keys in PEM format for evaluation of JWTs and message signatures.
* **Key Management:**
    * Asymmetric key pair generation in a secure way.
    * Checking for hardware-backed key storage (StrongBox).
* **Key Attestation:**
    * Demonstrates key attestation to verify the properties of the key pair.
    * Displays attestation certificate chains and details.
    * Verifies the attestation challenge (normally done in a server).
* **Application Signing Information:**
    * Displays the SHA-256 digests of the application's signing certificates.
    * Compares attestation certificates with the app's signatures (normally done in a server).
* **Device Integrity Verification:**
    * Verifies device's integrity status (Bootloader) for the attestation (normally done in a
      server).

![Screenshot](SCREENSHOT.webp)
