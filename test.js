const dilithium = require('./dist/index.js');

async function test() {
	console.log('=== Dilithium5 fork test ===\n');

	const seedBytesCount = await dilithium.seedBytes;
	console.log('seedBytes:', seedBytesCount);

	// Random keypair
	const kp1 = await dilithium.keyPair();
	console.log('keyPair() OK — pk:', kp1.publicKey.length, 'bytes, sk:', kp1.privateKey.length, 'bytes');

	// Deterministic keypair from seed
	const seed = new Uint8Array(seedBytesCount);
	for (let i = 0; i < seedBytesCount; i++) seed[i] = i;

	const kp2 = await dilithium.keyPairFromSeed(seed);
	console.log('keyPairFromSeed() OK — pk:', kp2.publicKey.length, 'bytes, sk:', kp2.privateKey.length, 'bytes');

	// Determinism: same seed = same keypair
	const kp3 = await dilithium.keyPairFromSeed(seed);
	const pkMatch = kp2.publicKey.every((b, i) => b === kp3.publicKey[i]);
	const skMatch = kp2.privateKey.every((b, i) => b === kp3.privateKey[i]);
	console.log('Determinism — pk match:', pkMatch, ', sk match:', skMatch);
	if (!pkMatch || !skMatch) throw new Error('FAIL: same seed produced different keys');

	// Different seed = different keypair
	const seed2 = new Uint8Array(seedBytesCount);
	seed2[0] = 0xFF;
	const kp4 = await dilithium.keyPairFromSeed(seed2);
	const different = !kp2.publicKey.every((b, i) => b === kp4.publicKey[i]);
	console.log('Different seed — different pk:', different);
	if (!different) throw new Error('FAIL: different seeds produced same keys');

	// Sign + verify with seeded keypair
	const msg = new Uint8Array([1, 2, 3, 4, 5]);
	const sig = await dilithium.signDetached(msg, kp2.privateKey);
	const valid = await dilithium.verifyDetached(sig, msg, kp2.publicKey);
	console.log('signDetached + verifyDetached:', valid);
	if (!valid) throw new Error('FAIL: signature verification failed');

	// Verify with wrong key fails
	const invalid = await dilithium.verifyDetached(sig, msg, kp1.publicKey);
	console.log('Wrong key verify:', !invalid ? 'correctly rejected' : 'ERROR');
	if (invalid) throw new Error('FAIL: wrong key accepted');

	// Seed validation
	try {
		await dilithium.keyPairFromSeed(new Uint8Array(16));
		throw new Error('FAIL: should have thrown for wrong seed length');
	} catch (e) {
		if (e.message.includes('seed must be')) {
			console.log('Seed length check: correctly rejected');
		} else {
			throw e;
		}
	}

	console.log('\n=== All tests passed ===');
}

test().catch(e => {
	console.error('TEST FAILED:', e.message);
	process.exit(1);
});
