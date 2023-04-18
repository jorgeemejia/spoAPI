const crypto = require('crypto');

// Generate RSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'pkcs1',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs1',
    format: 'pem'
  }
});

// Message to sign
const message = 'Hello, world!';

// Create signature
const sign = crypto.createSign('RSA-SHA256');
sign.write(message);
sign.end();
const signature = sign.sign(privateKey, 'base64');

console.log('Public key:', publicKey);
console.log('Signature:', signature);