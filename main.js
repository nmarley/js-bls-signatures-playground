const bls = require('bls-signatures');
const assert = require('assert');

const { PrivateKey } = bls;

// Constants defined in test vectors
const seed = Uint8Array.from([1, 2, 3, 4, 5]);
const msg = Uint8Array.from([7, 8, 9]);

// Go!

// Verify secret key matches test vector for genkey
const sk = PrivateKey.fromSeed(seed);
const skString = Buffer.from(sk.serialize()).toString('hex');
assert.strictEqual(skString, "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e");

// Verify signature matches test vector
const sig = sk.sign(msg);
const sigString = Buffer.from(sig.serialize()).toString('hex');
assert.strictEqual(sigString, "93eb2e1cb5efcfb31f2c08b235e8203a67265bc6a13d9f0ab77727293b74a357ff0459ac210dc851fcb8a60cb7d393a419915cfcf83908ddbeac32039aaa3e8fea82efcb3ba4f740f20c76df5e97109b57370ae32d9b70d256a98942e5806065");

// Verify valid signature
const isValidSignature = sig.verify();
assert.strictEqual(isValidSignature, true);

// Verify pubkey fingerprint
const pk = sk.getPublicKey();
const fp = pk.getFingerprint();
assert.strictEqual(fp, 0x26d53247);
