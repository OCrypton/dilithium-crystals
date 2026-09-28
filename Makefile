SOURCES = \
	pqclean_common/randombytes.c \
	pqclean_common/aes.c \
	pqclean_common/fips202.c \
	pqclean_common/nistseedexpander.c \
	pqclean_common/sha2.c \
	pqclean_common/sp800-185.c \
	pqclean_dilithium5/ntt.c \
	pqclean_dilithium5/packing.c \
	pqclean_dilithium5/poly.c \
	pqclean_dilithium5/polyvec.c \
	pqclean_dilithium5/reduce.c \
	pqclean_dilithium5/rounding.c \
	pqclean_dilithium5/sign.c \
	pqclean_dilithium5/symmetric-shake.c \
	main.c

INCLUDES = -Ipqclean_common -Ipqclean_dilithium5

EXPORTS = -s EXPORTED_FUNCTIONS="[ \
	'_free', \
	'_malloc', \
	'_dilithiumjs_keypair', \
	'_dilithiumjs_keypair_from_seed', \
	'_dilithiumjs_sign', \
	'_dilithiumjs_verify', \
	'_dilithiumjs_public_key_bytes', \
	'_dilithiumjs_secret_key_bytes', \
	'_dilithiumjs_signature_bytes', \
	'_dilithiumjs_seed_bytes' \
]" -s EXPORTED_RUNTIME_METHODS="['writeArrayToMemory','HEAPU8']"

EMCC_FLAGS = \
	-s SINGLE_FILE=1 \
	-s TOTAL_MEMORY=16777216 -s TOTAL_STACK=8388608 \
	-s ASSERTIONS=0 \
	-s AGGRESSIVE_VARIABLE_ELIMINATION=1 \
	-s ALIASING_FUNCTION_POINTERS=1 \
	-s NO_FILESYSTEM=1 \
	-s ERROR_ON_UNDEFINED_SYMBOLS=0

all:
	make clean
	emcc -O3 -s WASM=1 $(EMCC_FLAGS) $(INCLUDES) $(SOURCES) $(EXPORTS) -o dist/index.wasm.js

	cp pre.js dist/index.tmp.js
	echo " \
		var moduleReady = new Promise(function (resolve, reject) { \
			var Module = {}; \
			Module.onAbort = reject; \
			Module.onRuntimeInitialized = function () { \
				try { \
					Module._dilithiumjs_public_key_bytes(); \
					resolve(Module); \
				} \
				catch (err) { \
					reject(err); \
				} \
			}; \
	" >> dist/index.tmp.js
	cat dist/index.wasm.js >> dist/index.tmp.js
	echo " \
		}); \
	" >> dist/index.tmp.js
	cat post.js >> dist/index.tmp.js

	npx terser dist/index.tmp.js -cmo dist/index.js
	rm -rf dist/index.*.js
	chmod -R 777 dist

clean:
	rm -rf dist 2> /dev/null
	mkdir dist

test:
	node test.js
