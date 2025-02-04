# Dirsend

Send directories and files across the network easily, quickly and securely.

Simply run the executable and follow the instructions, usable even for non-technical people (eg. by giving them instructions over the phone).

## Usage

0. [Download](https://github.com/kovaxis/dirsend/releases) or compile the `dirsend` binary on both the sender and receiver.
1. Run `dirsend` on the sender.
2. Select your file and password.
3. Run `dirsend` on the receiver.
4. Enter IP address and password.
5. Transfer your files.

## Features

- Seamlessly `tar`s directories and un-`tar`s them on the other end.
- Applies quick compression using `gzip`.
- Encrypts files during transmission with AES, using Argon2id for key derivation from simple passwords.

## Limitations

- Currently does not support NAT hole-punching or any automatic relaying. The receiver must be able to reach an open port on the sender.
- Only interactive usage, no batch command mode.
- Little to no customization.
