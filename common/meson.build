# for i in $(ls *.c | sort); do echo "'$i',"; done
common_src = files([
	'binhexbin.c',
	'buffer.c',
	'esdm_logger.c',
	'helper.c',
	'linux_support.c',
	'threading_support.c',
])

if get_option('systemd').enabled()
	common_src += files(['systemd_support.c'])
endif

if get_option('testmode').enabled()
	common_src += files(['test_pertubation.c'])
endif

if get_option('fips140')
	common_src += files(['fips_integrity.c'])
endif

conf_data = configuration_data()

conf_data.set('ESDM_SYSTEMD_SUPPORT', get_option('systemd').enabled())

conf_data.set('ESDM_OVERSAMPLE_ENTROPY_SOURCES',
	      get_option('sp80090c') or get_option('fips140'))
conf_data.set('ESDM_AIS2031_NTG1_SEEDING_STRATEGY', get_option('ais2031_ntg1'))
if get_option('sp80090c') or get_option('fips140')
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 128)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 64)
else
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 0)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 0)
endif

if get_option('crypto_backend') == 'builtin'
	conf_data.set('ESDM_DRNG_HASH_DRBG', get_option('drng_hash_drbg').enabled())
	conf_data.set('ESDM_DRNG_CHACHA20', get_option('drng_chacha20').enabled())
	conf_data.set('ESDM_HASH_SHA512', get_option('hash_sha512').enabled())
	conf_data.set('ESDM_HASH_SHA3_512', get_option('hash_sha3_512').enabled())
else
	conf_data.set('ESDM_DRNG_HASH_DRBG', false)
	conf_data.set('ESDM_DRNG_CHACHA20', false)
	conf_data.set('ESDM_HASH_SHA512', false)
	conf_data.set('ESDM_HASH_SHA3_512', false)
endif

if get_option('crypto_backend') == 'gnutls'
	conf_data.set('ESDM_GNUTLS', true)
else
	conf_data.set('ESDM_GNUTLS', false)
endif

if get_option('crypto_backend') == 'leancrypto'
	conf_data.set('ESDM_LEANCRYPTO', true)
else
	conf_data.set('ESDM_LEANCRYPTO', false)
endif

if get_option('crypto_backend') == 'openssl'
	conf_data.set('ESDM_OPENSSL', true)
else
	conf_data.set('ESDM_OPENSSL', false)
endif

if get_option('crypto_backend') == 'botan'
	conf_data.set('ESDM_BOTAN', true)
else
	conf_data.set('ESDM_BOTAN', false)
endif

conf_data.set('ESDM_OPENSSL_DRNG_CTR', get_option('openssl_drng_type') == 'ctr')
conf_data.set('ESDM_OPENSSL_DRNG_HASH', get_option('openssl_drng_type') == 'hash')
conf_data.set('ESDM_OPENSSL_DRNG_HMAC', get_option('openssl_drng_type') == 'hmac')

conf_data.set('ESDM_BOTAN_DRNG_CHACHA20', get_option('botan_drng_type') == 'chacha20')
conf_data.set('ESDM_BOTAN_DRNG_HMAC', get_option('botan_drng_type') == 'hmac')

conf_data.set('THREADING_MAX_WORKER_THREADS', get_option('threading_max_worker_threads'))
conf_data.set('THREADING_MAX_THREADS', get_option('threading_max_worker_threads') + 3)

conf_data.set('ESDM_ES_PARALLEL_FETCH', get_option('es_parallel_fetch').enabled())

conf_data.set('ESDM_ES_JENT', get_option('es_jent').enabled())
conf_data.set('ESDM_JENT_ENTROPY_RATE',
	      get_option('es_jent_entropy_rate'))
conf_data.set('ESDM_JENT_OSR',
	      get_option('es_jent_osr'))
conf_data.set('ESDM_JENT_NTG1',
	      get_option('es_jent_ntg1').enabled())
conf_data.set('ESDM_JENT_MAX_MEM',
	      get_option('es_jent_max_mem'))
conf_data.set('ESDM_JENT_HASH_LOOP_COUNT',
	      get_option('es_jent_hash_loop_count'))
conf_data.set('ESDM_JENT_ALL_CACHES',
	      get_option('es_jent_all_caches').enabled())

# Async per-ES buffering (es_buf) is incompatible with SP800-90C oversampled
# seeding by default. When sp80090c is set, zero out every ESDM_*_ENTROPY_BLOCKS
# count so esdm_es_buf compiles out of all ES sources. The es_buf_force option
# overrides this and keeps the per-ES counts honored.
disable_es_buf = get_option('sp80090c') and not get_option('es_buf_force')

# In esdm_es_jent.c the ESDM_JENT_ENTROPY_BLOCKS are divided by 4 and yet
# need to result in a value larger than zero
if get_option('es_jent_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_JENT_ENTROPY_BLOCKS',
		      get_option('es_jent_entropy_blocks'))
else
	conf_data.set('ESDM_JENT_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_CPU', get_option('es_cpu').enabled())
conf_data.set('ESDM_CPU_ENTROPY_RATE',
	      get_option('es_cpu_entropy_rate'))
conf_data.set('ESDM_CPU_FULL_ENT_MULTIPLIER',
	      get_option('es_cpu_multiplier'))

conf_data.set('ESDM_ES_IRQ', get_option('es_irq').enabled())
conf_data.set('ESDM_IRQ_ENTROPY_RATE',
	      get_option('es_irq_entropy_rate'))
if get_option('es_irq_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_IRQ_ENTROPY_BLOCKS',
		      get_option('es_irq_entropy_blocks'))
else
	conf_data.set('ESDM_IRQ_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_KERNEL_RNG', get_option('es_kernel').enabled())
conf_data.set('ESDM_KERNEL_RNG_ENTROPY_RATE',
	      get_option('es_kernel_entropy_rate'))

conf_data.set('ESDM_ES_SCHED', get_option('es_sched').enabled())
conf_data.set('ESDM_SCHED_ENTROPY_RATE',
	      get_option('es_sched_entropy_rate'))
if get_option('es_sched_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_SCHED_ENTROPY_BLOCKS',
		      get_option('es_sched_entropy_blocks'))
else
	conf_data.set('ESDM_SCHED_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_SCHED_EBPF', get_option('es_sched_ebpf').enabled())
conf_data.set('ESDM_SCHED_EBPF_ENTROPY_RATE',
	      get_option('es_sched_ebpf_entropy_rate'))
conf_data.set('ESDM_SCHED_EBPF_OSR',
	      get_option('es_sched_ebpf_osr'))

conf_data.set('ESDM_ES_IRQ_EBPF', get_option('es_irq_ebpf').enabled())
conf_data.set('ESDM_IRQ_EBPF_ENTROPY_RATE',
	      get_option('es_irq_ebpf_entropy_rate'))
conf_data.set('ESDM_IRQ_EBPF_OSR',
	      get_option('es_irq_ebpf_osr'))

conf_data.set('ESDM_ES_EBPF_TESTING', get_option('es_ebpf_testing').enabled())

conf_data.set('ESDM_ES_HWRAND', get_option('es_hwrand').enabled())
conf_data.set('ESDM_HWRAND_ENTROPY_RATE',
	      get_option('es_hwrand_entropy_rate'))
if get_option('es_hwrand_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_HWRAND_ENTROPY_BLOCKS',
		      get_option('es_hwrand_entropy_blocks'))
else
	conf_data.set('ESDM_HWRAND_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_TPM2', get_option('es_tpm2').enabled())
conf_data.set('ESDM_TPM2_ENTROPY_RATE',
	      get_option('es_tpm2_entropy_rate'))
conf_data.set('ESDM_TPM2_STIR', get_option('es_tpm2_stir').enabled())
conf_data.set_quoted('ESDM_TPM2_RM_PATH', get_option('es_tpm2_rm_path'))
if get_option('es_tpm2_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_TPM2_ENTROPY_BLOCKS',
		      get_option('es_tpm2_entropy_blocks'))
else
	conf_data.set('ESDM_TPM2_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_PKCS11', get_option('es_pkcs11').enabled())
conf_data.set('ESDM_PKCS11_ENTROPY_RATE',
	      get_option('es_pkcs11_entropy_rate'))
conf_data.set_quoted('ESDM_PKCS11_MODULE_PATH',
		     get_option('es_pkcs11_module_path'))
conf_data.set_quoted('ESDM_PKCS11_TOKEN_LABEL',
		     get_option('es_pkcs11_token_label'))
conf_data.set_quoted('ESDM_PKCS11_PIN', get_option('es_pkcs11_pin'))
if get_option('es_pkcs11_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_PKCS11_ENTROPY_BLOCKS',
		      get_option('es_pkcs11_entropy_blocks'))
else
	conf_data.set('ESDM_PKCS11_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_JENT_KERNEL', get_option('es_jent_kernel').enabled())
conf_data.set('ESDM_JENT_KERNEL_ENTROPY_RATE',
	      get_option('es_jent_kernel_entropy_rate'))
if get_option('es_jent_kernel_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_JENT_KERNEL_ENTROPY_BLOCKS',
		      get_option('es_jent_kernel_entropy_blocks'))
else
	conf_data.set('ESDM_JENT_KERNEL_ENTROPY_BLOCKS', 0)
endif

timing_es_credited = 0
foreach timing_es_rate_option : [ 'es_irq_entropy_rate',
				  'es_sched_entropy_rate',
				  'es_irq_ebpf_entropy_rate',
				  'es_sched_ebpf_entropy_rate' ]
	if get_option(timing_es_rate_option) > 0
		timing_es_credited += 1
	endif
endforeach
if timing_es_credited > 1
	error('It is not permissible to award more than one of the interrupt and scheduler-based entropy sources (es_irq, es_sched, es_irq_ebpf, es_sched_ebpf) an entropy rate greater than zero. Adjust the respective entropy rate options to zero.')
endif

conf_data.set('ESDM_SELINUX_ENABLED', get_option('selinux').enabled())
conf_data.set('ESDM_NODE', get_option('node').enabled())
conf_data.set('ESDM_FIPS140', get_option('fips140'))

conf_data.set('ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT', get_option('client-connect-timeout-exponent'))
conf_data.set('ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT', get_option('client-rx-tx-timeout-exponent'))
conf_data.set('ESDM_CLIENT_RECONNECT_ATTEMPTS', get_option('client-reconnect-attempts'))
conf_data.set('ESDM_MAX_RX_TX_RETRIES', 5)

# chunk pr requests, such that slow entropy sources return fast in server
# and don't block the server longer than client read timeouts on average
conf_data.set('ESDM_RPC_MAX_PR_REQUEST_SIZE', 32)

conf_data.set('ESDM_TESTMODE', get_option('testmode').enabled())

conf_data.set('ESDM_GETRANDOM_NUM_NODES', get_option('linux-getrandom-num-nodes'))

conf_data.set('ESDM_LINUX_RESEED_INTERVAL_SEC', get_option('linux-reseed-interval'))
conf_data.set('ESDM_LINUX_RESEED_ENTROPY_COUNT', get_option('linux-reseed-entropy-count'))

if get_option('sp80090c') or get_option('ais2031_drg4')
	reseed_thresh = get_option('drng_reseed_threshold_bits')
	max_reseed = get_option('drng_max_reseed_bits')

	# SP800-90C and AIS 20/31 DRG.4.10 cap the bits a DRNG may produce
	# without a full reseed at 2**17.
	if max_reseed > 131072
		max_reseed = 131072
	endif

	# Where inside that limit the reseed is triggered decides two things
	# that pull against each other: how often the entropy sources are
	# walked, and how much output a DRNG has left to cover the walk with.
	# The reseed of a node DRNG is handed to a worker, and everything the
	# DRNG may still produce before the limit above is the budget that
	# worker has to finish in.
	#
	# Three quarters, measured rather than picked: reseeding is expensive
	# enough that the frequency dominates. Moving the trigger from a half to
	# three quarters gains 13-16% throughput, and the remaining quarter -
	# 32768 bits of output - is what the asynchronous reseed gets to land
	# in. Going further flattens out (87% and 100% add a few percent more)
	# and at the limit itself the headroom is gone: every node DRNG then
	# reaches the maximum at the moment it asks to be reseeded and drops out
	# of the fully seeded state until the worker catches up, which only a
	# machine with several nodes can absorb.
	if reseed_thresh > (max_reseed / 4) * 3
		reseed_thresh = (max_reseed / 4) * 3
	endif

	conf_data.set('ESDM_DRNG_RESEED_THRESH_BITS', reseed_thresh)
	conf_data.set('ESDM_DRNG_MAX_RESEED_BITS', max_reseed)
else
	conf_data.set('ESDM_DRNG_RESEED_THRESH_BITS', get_option('drng_reseed_threshold_bits'))
	conf_data.set('ESDM_DRNG_MAX_RESEED_BITS', get_option('drng_max_reseed_bits'))
endif

conf_data.set_quoted('ESDM_SERVER_RPC_BASE_PATH_UNPRIVILEGED', get_option('esdm-server-rpc-path-unprivileged'))
conf_data.set_quoted('ESDM_SERVER_RPC_BASE_PATH_PRIVILEGED', get_option('esdm-server-rpc-path-privileged'))

# Default socket of the optional EGD interface: where the esdm-server-egd.socket
# unit places it, and therefore where an EGD client looks for it unless it is
# told otherwise.
conf_data.set_quoted('ESDM_SERVER_EGD_SOCKET_PATH', get_option('esdm-server-egd-socket-path'))
conf_data.set_quoted('ESDM_SERVER_EGD_PR_SOCKET_PATH', get_option('esdm-server-egd-pr-socket-path'))

conf_data.set('ESDM_RPC_IDLE_TIMEOUT_USEC', get_option('esdm-server-rpc-idle-timeout-usec'))

conf_data.set('ESDM_HAS_AUX_CLIENT', get_option('esdm-aux-client').enabled())

conf_data.set('ESDM_NUM_AUX_POOLS', get_option('num-aux-pools'))
conf_data.set('ESDM_AUX_INPUT_HAS_FULL_ENTROPY', get_option('aux-has-full-entropy').enabled())

conf_data.set('ESDM_MEMORY_DEBUG', get_option('memory-debug').enabled())

configure_file(output: 'config.h', configuration : conf_data)
