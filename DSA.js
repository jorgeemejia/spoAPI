const crypto = require('crypto');

// Generate DSA key pair with modulus length 2048
const { privateKey, publicKey } = crypto.generateKeyPairSync('dsa', {
  modulusLength: 2048,
});

const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' });

console.log('Private key (PEM):', privateKeyPem);
console.log('Public key (PEM):', publicKeyPem);

