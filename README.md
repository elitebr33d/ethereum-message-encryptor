# Ethereum Wallet Secure Messenger

A secure communication tool that uses Ethereum wallet cryptography to enable private messaging between parties. This script allows users to encrypt messages that can only be decrypted by a specific Ethereum wallet address.

## Features

- **Wallet Management**: Automatically generates an Ethereum wallet and securely stores it as `wallet.json`
- **End-to-End Encryption**: Uses Ethereum's elliptic curve cryptography for secure messaging
- **Easy Key Exchange**: Share only your public key to receive encrypted messages
- **No Blockchain Required**: Works offline using only the cryptographic principles of Ethereum wallets
- **Perfect Forward Secrecy**: Generates new ephemeral keys for each message

## Installation

1. Make sure you have [Node.js](https://nodejs.org/) installed (version 12.0.0 or higher recommended)
2. Clone this repository or download the script file
3. Install dependencies:

```bash
npm install
```

## Usage

### Running the Script

```bash
npm run start
```

On first run, the script generates a new Ethereum wallet and saves it as `wallet.json` in the same directory.

### Workflow

1. **Initial Setup**
   - The first time you run the script, it creates your personal Ethereum wallet
   - The script displays your wallet address and public key
   - Share your public key with people you want to receive messages from

2. **Sending a Message**
   - Select option 1 from the menu
   - Enter the recipient's public key
   - Type your message
   - The script outputs encrypted message data in JSON format
   - Send this JSON data to your recipient through any channel

3. **Receiving a Message**
   - Select option 2 from the menu
   - Paste the encrypted JSON data you received
   - The script will decrypt and display the message

## Security

This messenger implements a variation of ECIES (Elliptic Curve Integrated Encryption Scheme):

1. Generates a random symmetric key to encrypt the actual message
2. Uses the recipient's public key to securely encrypt the symmetric key
3. Only the holder of the corresponding private key can decrypt the symmetric key and thus the message

**Note**: Keep your `wallet.json` file secure! Anyone with access to this file can decrypt messages intended for you.

## How It Works

### Encryption Process

1. A random symmetric key is generated for encrypting the message
2. The message is encrypted with AES-256-CBC using this symmetric key
3. An ephemeral key pair is created for this specific message
4. A shared secret is computed between the ephemeral private key and recipient's public key
5. The symmetric key is encrypted using a derived key from the shared secret
6. All necessary components for decryption are bundled together

### Decryption Process

1. The recipient computes the same shared secret using their private key and the ephemeral public key
2. The derived key is used to decrypt the symmetric key
3. The symmetric key is used to decrypt the message

## Advanced Use Cases

- **Group Messaging**: Encrypt the same message multiple times, once for each recipient
- **Offline Communication**: Exchange encrypted messages via any channel (email, USB drive, etc.)
- **Identity Verification**: The wallet address serves as proof of identity

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.