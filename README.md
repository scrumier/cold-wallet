# cold-wallet

An air-gapped cryptocurrency wallet written in Rust.

## What it does

This wallet is designed to sign transactions on a device that never connects to the internet. No Wi-Fi. No Bluetooth. No USB. The only communication channel is QR codes.

The workflow:
1. Build an unsigned transaction on an online device, export it as a QR code
2. Scan the QR code on the offline device running this wallet
3. The wallet signs the transaction with the private key
4. The signed transaction is displayed as a QR code
5. Scan it back on the online device and broadcast it to the network

The private key never touches a connected device.

## Why

Hardware wallets exist, but they are black boxes. This project is an attempt to understand what air-gapped signing actually requires — key generation, transaction parsing, cryptographic signing — by building it from scratch.

## Status

Experimental and educational. Not audited. Not recommended for storing real funds.

## Stack

- Rust
- QR code encoding/decoding
- Standard cryptographic primitives

## Author

Sonam — [github.com/scrumier](https://github.com/scrumier)
