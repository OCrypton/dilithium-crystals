;

function dataReturn (returnValue, result) {
	if (returnValue === 0) {
		return result;
	}
	else {
		throw new Error('Dilithium error: ' + returnValue);
	}
}

function dataResult (mod, buffer, byteLength) {
	return new Uint8Array(
		new Uint8Array(mod.HEAPU8.buffer, buffer, byteLength)
	);
}

function dataFree (mod, buffer) {
	try {
		mod._free(buffer);
	}
	catch (err) {
		setTimeout(function () { throw err; }, 0);
	}
}


var publicKeyBytes, privateKeyBytes, bytes, seedBytes;

var initiated	= moduleReady.then(function (m) {
	publicKeyBytes	= m._dilithiumjs_public_key_bytes();
	privateKeyBytes	= m._dilithiumjs_secret_key_bytes();
	bytes			= m._dilithiumjs_signature_bytes();
	seedBytes		= m._dilithiumjs_seed_bytes();
	return m;
});


var dilithium	= {
	publicKeyBytes: initiated.then(function () { return publicKeyBytes; }),
	privateKeyBytes: initiated.then(function () { return privateKeyBytes; }),
	bytes: initiated.then(function () { return bytes; }),
	seedBytes: initiated.then(function () { return seedBytes; }),

	keyPair: function () { return initiated.then(function (mod) {
		var publicKeyBuffer		= mod._malloc(publicKeyBytes);
		var privateKeyBuffer	= mod._malloc(privateKeyBytes);

		try {
			var returnValue	= mod._dilithiumjs_keypair(
				publicKeyBuffer,
				privateKeyBuffer
			);

			return dataReturn(returnValue, {
				publicKey: dataResult(mod, publicKeyBuffer, publicKeyBytes),
				privateKey: dataResult(mod, privateKeyBuffer, privateKeyBytes)
			});
		}
		finally {
			dataFree(mod, publicKeyBuffer);
			dataFree(mod, privateKeyBuffer);
		}
	}); },

	keyPairFromSeed: function (seed) { return initiated.then(function (mod) {
		if (!(seed instanceof Uint8Array) || seed.length !== seedBytes) {
			throw new Error('Dilithium seed must be ' + seedBytes + ' bytes');
		}

		var publicKeyBuffer		= mod._malloc(publicKeyBytes);
		var privateKeyBuffer	= mod._malloc(privateKeyBytes);
		var seedBuffer			= mod._malloc(seedBytes);

		mod.writeArrayToMemory(seed, seedBuffer);

		try {
			var returnValue	= mod._dilithiumjs_keypair_from_seed(
				publicKeyBuffer,
				privateKeyBuffer,
				seedBuffer
			);

			return dataReturn(returnValue, {
				publicKey: dataResult(mod, publicKeyBuffer, publicKeyBytes),
				privateKey: dataResult(mod, privateKeyBuffer, privateKeyBytes)
			});
		}
		finally {
			dataFree(mod, publicKeyBuffer);
			dataFree(mod, privateKeyBuffer);
			dataFree(mod, seedBuffer);
		}
	}); },

	sign: function (message, privateKey) {
		return dilithium.signDetached(message, privateKey).then(function (signature) {
			var signed	= new Uint8Array(bytes + message.length);
			signed.set(signature);
			signed.set(message, bytes);
			return signed;
		});
	},

	signDetached: function (message, privateKey) { return initiated.then(function (mod) {
		var signatureBuffer		= mod._malloc(bytes);
		var messageBuffer		= mod._malloc(message.length);
		var privateKeyBuffer	= mod._malloc(privateKeyBytes);

		mod.writeArrayToMemory(new Uint8Array(bytes), signatureBuffer);
		mod.writeArrayToMemory(message, messageBuffer);
		mod.writeArrayToMemory(privateKey, privateKeyBuffer);

		try {
			var returnValue	= mod._dilithiumjs_sign(
				signatureBuffer,
				messageBuffer,
				message.length,
				privateKeyBuffer
			);

			return dataReturn(returnValue, dataResult(mod, signatureBuffer, bytes));
		}
		finally {
			dataFree(mod, signatureBuffer);
			dataFree(mod, messageBuffer);
			dataFree(mod, privateKeyBuffer);
		}
	}); },

	open: function (signed, publicKey) { return initiated.then(function () {
		var signature	= new Uint8Array(signed.buffer, signed.byteOffset, bytes);
		var message		= new Uint8Array(
			signed.buffer,
			signed.byteOffset + bytes,
			signed.length - bytes
		);

		return dilithium.verifyDetached(signature, message, publicKey).then(function (isValid) {
			if (isValid) {
				return message;
			}
			else {
				throw new Error('Failed to open Dilithium signed message.');
			}
		});
	}); },

	verifyDetached: function (signature, message, publicKey) {
		return initiated.then(function (mod) {
			var signatureBuffer	= mod._malloc(bytes);
			var messageBuffer	= mod._malloc(message.length);
			var publicKeyBuffer	= mod._malloc(publicKeyBytes);

			mod.writeArrayToMemory(signature, signatureBuffer);
			mod.writeArrayToMemory(message, messageBuffer);
			mod.writeArrayToMemory(publicKey, publicKeyBuffer);

			try {
				var returnValue	= mod._dilithiumjs_verify(
					messageBuffer,
					message.length,
					signatureBuffer,
					publicKeyBuffer
				);

				return returnValue === 0;
			}
			finally {
				dataFree(mod, signatureBuffer);
				dataFree(mod, messageBuffer);
				dataFree(mod, publicKeyBuffer);
			}
		});
	}
};



return dilithium;

}());


if (typeof module !== 'undefined' && module.exports) {
	dilithium.dilithium	= dilithium;
	module.exports	= dilithium;
}
else {
	self.dilithium	= dilithium;
}
