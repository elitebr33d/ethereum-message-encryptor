// Ethereum Wallet Secure Messenger
// This script enables secure messaging between Ethereum wallet owners
// using asymmetric encryption

const fs = require('fs');
const crypto = require('crypto');
const ethers = require('ethers');
const readline = require('readline');

const WALLET_FILE = 'wallet.json';

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Function to generate or load an Ethereum wallet
async function getWallet() {
  try {
    if (fs.existsSync(WALLET_FILE)) {
      const data = fs.readFileSync(WALLET_FILE, 'utf8');
      const json = JSON.parse(data);
      const wallet = new ethers.Wallet(json.privateKey);
      
      // If the wallet already has the public key in the file, use it
      if (json.publicKey) {
        wallet.publicKey = json.publicKey;
        return wallet;
      }
      
      // Otherwise, we need to compute or derive the public key
      let publicKey;
      
      // Different ethers versions expose different methods to get the public key
      try {
        // Try to get the public key directly from the wallet first
        if (wallet.publicKey) {
          publicKey = wallet.publicKey;
        } 
        // Or try signingKey if that's available
        else if (wallet.signingKey && wallet.signingKey.publicKey) {
          publicKey = wallet.signingKey.publicKey;
        }
        // Try with compressedPublicKey (some ethers versions)
        else if (wallet.compressedPublicKey) {
          publicKey = wallet.compressedPublicKey;
        }
        // If none of the above worked, derive it manually using elliptic library
        else {
          // We'll derive the public key from the private key
          console.log("Deriving public key from private key...");
          
          // For ethers v5
          if (ethers.utils && ethers.utils.computePublicKey) {
            publicKey = ethers.utils.computePublicKey(wallet.privateKey, true);
          }
          // For ethers v6
          else if (ethers.computePublicKey) {
            publicKey = ethers.computePublicKey(wallet.privateKey, true);
          }
          // If we can't compute directly with ethers utilities
          else {
            console.log("Using crypto module to derive public key");
            // Use the crypto module to derive the public key
            const ecdh = crypto.createECDH('secp256k1');
            // Convert private key to proper format (remove 0x prefix if present)
            const privateKeyHex = wallet.privateKey.startsWith('0x') ? 
              wallet.privateKey.slice(2) : wallet.privateKey;
            ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
            publicKey = '0x' + ecdh.getPublicKey('hex', 'compressed');
          }
        }
        
        // Update the wallet object with the public key
        wallet.publicKey = publicKey;
        
        // Update the wallet.json file
        const walletData = {
          address: wallet.address,
          privateKey: wallet.privateKey,
          publicKey: publicKey
        };
        fs.writeFileSync(WALLET_FILE, JSON.stringify(walletData, null, 2));
        console.log(`Wallet file updated with public key information.`);
        
        return wallet;
      } catch (keyError) {
        console.error(`Error deriving public key: ${keyError.message}`);
        console.error(`Please provide your public key manually and update the wallet.json file.`);
        process.exit(1);
      }
    } else {
      // Generate a new wallet
      const wallet = ethers.Wallet.createRandom();
      let publicKey;
      
      // Try to get the public key using different ethers versions
      try {
        if (wallet.publicKey) {
          publicKey = wallet.publicKey;
        } else if (wallet.signingKey && wallet.signingKey.publicKey) {
          publicKey = wallet.signingKey.publicKey;
        } else if (ethers.utils && ethers.utils.computePublicKey) {
          publicKey = ethers.utils.computePublicKey(wallet.privateKey, true);
        } else if (ethers.computePublicKey) {
          publicKey = ethers.computePublicKey(wallet.privateKey, true);
        } else {
          const ecdh = crypto.createECDH('secp256k1');
          const privateKeyHex = wallet.privateKey.startsWith('0x') ? 
            wallet.privateKey.slice(2) : wallet.privateKey;
          ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
          publicKey = '0x' + ecdh.getPublicKey('hex', 'compressed');
        }
        
        wallet.publicKey = publicKey;
        
        // Save wallet to file
        const walletData = {
          address: wallet.address,
          privateKey: wallet.privateKey,
          publicKey: publicKey
        };
        
        fs.writeFileSync(WALLET_FILE, JSON.stringify(walletData, null, 2));
        console.log(`New wallet created and saved to ${WALLET_FILE}`);
        return wallet;
      } catch (keyError) {
        console.error(`Error generating public key: ${keyError.message}`);
        process.exit(1);
      }
    }
  } catch (error) {
    console.error(`Error with wallet: ${error.message}`);
    process.exit(1);
  }
}

// Encrypt a message that only the recipient can decrypt
async function encryptMessage(message, recipientPublicKey) {
  try {
    // Remove the '0x04' prefix if present (Ethereum public keys often include this prefix)
    const pubKeyHex = recipientPublicKey.startsWith('0x') ? 
      recipientPublicKey.slice(2) : recipientPublicKey;
    
    // Generate a random symmetric key for this message
    const symmetricKey = crypto.randomBytes(32);
    
    // Encrypt the message with the symmetric key
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
    let encryptedMessage = cipher.update(message, 'utf8', 'hex');
    encryptedMessage += cipher.final('hex');
    
    // Use ECIES-like approach to encrypt the symmetric key with recipient's public key
    // For this, we'll use the Node.js ECDH API
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    
    // Import recipient's public key
    const recipientPubPoint = Buffer.from(pubKeyHex, 'hex');
    
    // Derive shared secret
    const sharedSecret = ecdh.computeSecret(recipientPubPoint);
    
    // Use HKDF to derive encryption key from shared secret
    const derivedKey = crypto.createHash('sha256').update(sharedSecret).digest();
    
    // Encrypt symmetric key with derived key
    const keyIv = crypto.randomBytes(16);
    const keyCipher = crypto.createCipheriv('aes-256-cbc', derivedKey, keyIv);
    let encryptedKey = keyCipher.update(symmetricKey);
    encryptedKey = Buffer.concat([encryptedKey, keyCipher.final()]);
    
    // Return all necessary components for decryption
    return {
      encryptedMessage,
      iv: iv.toString('hex'),
      encryptedKey: encryptedKey.toString('hex'),
      keyIv: keyIv.toString('hex'),
      ephemeralPublicKey: ecdh.getPublicKey('hex')
    };
  } catch (error) {
    console.error(`Encryption error: ${error.message}`);
    return null;
  }
}

// Decrypt a message using the wallet's private key
async function decryptMessage(encryptedData, wallet) {
  try {
    // Extract all components
    const { encryptedMessage, iv, encryptedKey, keyIv, ephemeralPublicKey } = encryptedData;
    
    // Create ECDH instance with our private key
    const privateKeyBuffer = Buffer.from(wallet.privateKey.slice(2), 'hex');
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKeyBuffer);
    
    // Compute the same shared secret
    const ephemeralPubKeyBuffer = Buffer.from(ephemeralPublicKey, 'hex');
    const sharedSecret = ecdh.computeSecret(ephemeralPubKeyBuffer);
    
    // Derive the same encryption key
    const derivedKey = crypto.createHash('sha256').update(sharedSecret).digest();
    
    // Decrypt the symmetric key
    const keyIvBuffer = Buffer.from(keyIv, 'hex');
    const keyDecipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, keyIvBuffer);
    let decryptedKey = keyDecipher.update(Buffer.from(encryptedKey, 'hex'));
    decryptedKey = Buffer.concat([decryptedKey, keyDecipher.final()]);
    
    // Use the symmetric key to decrypt the message
    const ivBuffer = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', decryptedKey, ivBuffer);
    let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
    decryptedMessage += decipher.final('utf8');
    
    return decryptedMessage;
  } catch (error) {
    console.error(`Decryption error: ${error.message}`);
    return null;
  }
}

// Main function
async function main() {
  try {
    const wallet = await getWallet();
    
    console.log(`\n----- YOUR WALLET INFO -----`);
    console.log(`Address: ${wallet.address}`);
    console.log(`Public Key: ${wallet.publicKey}`);
    console.log(`\nSHARE YOUR PUBLIC KEY WITH OTHERS SO THEY CAN SEND YOU ENCRYPTED MESSAGES\n`);
    
    rl.question('What would you like to do? (1: Send message, 2: Decrypt message): ', async (choice) => {
      if (choice === '1') {
        rl.question('Enter recipient\'s public key: ', (recipientPublicKey) => {
          rl.question('Enter your message: ', async (message) => {
            const encryptedData = await encryptMessage(message, recipientPublicKey);
            if (encryptedData) {
              console.log('\n----- ENCRYPTED MESSAGE DATA -----');
              console.log(JSON.stringify(encryptedData, null, 2));
              console.log('\nSend this entire JSON object to the recipient for decryption.');
            }
            rl.close();
          });
        });
      } else if (choice === '2') {
        rl.question('Paste the encrypted message data (JSON format): ', async (encryptedDataStr) => {
          try {
            const encryptedData = JSON.parse(encryptedDataStr);
            const decryptedMessage = await decryptMessage(encryptedData, wallet);
            if (decryptedMessage) {
              console.log('\n----- DECRYPTED MESSAGE -----');
              console.log(decryptedMessage);
            }
          } catch (error) {
            console.error('Invalid encrypted data format.');
          }
          rl.close();
        });
      } else {
        console.log('Invalid choice.');
        rl.close();
      }
    });
  } catch (error) {
    console.error(`Error: ${error.message}`);
    rl.close();
  }
}

// Run the main function
main();