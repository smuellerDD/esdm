# for i in $(ls *.c | sort); do echo "'$i',"; done
crypto_src = files([
	'hash.c',
	'hash_drbg.c',
	'hmac.c',
	'sha256.c',
	'sha512.c',
])

if get_option('drng_hash_drbg').enabled()
	crypto_src += files([
		'drbg.c',
	])
endif

if get_option('drng_chacha20').enabled()
	crypto_src += files([
		'chacha20.c',
		'chacha20_drng.c',
	])
endif
