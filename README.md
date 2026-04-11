# Secure File Rotation & Protection System 🛡️

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: AES-GCM](https://img.shields.io/badge/Security-AES--GCM-green.svg)](#)

## 📌 Overview
This repository contains a professional-grade file protection utility developed for the **Master's in Cybersecurity at Harokopio University of Athens**. The system implements a "Defense in Depth" strategy to ensure data **Confidentiality** and **Integrity** for Data-at-Rest.

The core innovation lies in the **Dynamic Key Rotation** mechanism, which enforces a unique cryptographic key per file access, significantly reducing the blast radius of a potential key compromise.

## ✨ Key Features
* **Cryptographic Agility:** User-selectable algorithms including **AES-GCM** and **ChaCha20-Poly1305**.
* **Automated Key Rotation:** Transparently rotates file keys after every successful decryption or integrity verification.
* **Hierarchical Key Management:** Secure key derivation from a Master Password using **PBKDF2** with high iteration counts (100k+).
* **Configurable Security Levels:** Support for both **128-bit** and **256-bit** security parameters.
* **Tamper Detection:** Built-in integrity checks using **AEAD** tags to prevent bit-flipping and unauthorized modifications.

## 📂 Project Structure
```text
├── src/                # Core cryptographic engine and CLI implementation
├── docs/               # Technical report (LaTeX), architecture diagrams, and KDF flow
├── tests/              # Integrity validation and key rotation test suites
├── requirements.txt    # Production dependencies
└── README.md           # Project documentation
