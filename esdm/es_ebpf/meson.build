# Build pipeline for the eBPF-based entropy sources: compile the *.bpf.c
# programs with clang for the BPF target and generate libbpf skeleton headers
# with bpftool. The programs only use the stable UAPI headers (no vmlinux.h /
# CO-RE machinery is needed as no kernel data structures are dereferenced),
# so the build does not depend on kernel BTF availability.

libbpf_dep = dependency('libbpf', version: '>= 1.2')
clang_bpf = find_program('clang')
bpftool = find_program('bpftool')

cpu = host_machine.cpu_family()
if cpu == 'x86_64'
	ebpf_arch_define = '-D__TARGET_ARCH_x86'
elif cpu == 'aarch64'
	ebpf_arch_define = '-D__TARGET_ARCH_arm64'
elif cpu == 'riscv64'
	ebpf_arch_define = '-D__TARGET_ARCH_riscv'
elif cpu == 'ppc64'
	ebpf_arch_define = '-D__TARGET_ARCH_powerpc'
elif cpu == 's390x'
	ebpf_arch_define = '-D__TARGET_ARCH_s390'
else
	error('eBPF entropy sources are not supported on CPU family ' + cpu)
endif

# -mcpu=v2 is the conservative choice for the supported kernel floor
# (5.15 x86_64 / 6.1 arm64)
ebpf_c_args = [
	'-g', '-O2',
	'-target', 'bpf',
	'-mcpu=v2',
	ebpf_arch_define,
	'-Wall', '-Wextra',
	'-I' + meson.current_build_dir(),
	'-I' + meson.current_source_dir(),
]

# clang with -target bpf does not search the multiarch include directory
# (e.g. /usr/include/x86_64-linux-gnu on Debian/Ubuntu) where asm/types.h
# lives - add it explicitly like the libbpf-tools do.
multiarch = run_command(cc.cmd_array()[0], '-print-multiarch',
			check: false).stdout().strip()
if multiarch != ''
	ebpf_c_args += '-idirafter/usr/include/' + multiarch
endif

# The Nix compiler wrapper injects host hardening flags (e.g.
# -fzero-call-used-regs=used-gpr) which the BPF target rejects - disable the
# injection for the BPF program compilation. The variable is only
# interpreted by the Nix wrapper and has no effect elsewhere.
ebpf_env = environment()
ebpf_env.set('NIX_HARDENING_ENABLE', '')

# Raw event recording support is only compiled into the eBPF programs for
# measurement builds - production programs do not contain the code path.
if get_option('es_ebpf_testing').enabled()
	ebpf_c_args += '-DESDM_ES_EBPF_TESTING'
endif

ebpf_progs = [ ]
if get_option('es_sched_ebpf').enabled()
	ebpf_progs += 'esdm_es_sched_ebpf'
endif
if get_option('es_irq_ebpf').enabled()
	ebpf_progs += 'esdm_es_irq_ebpf'
endif

esdm_ebpf_skel_hdrs = [ ]
foreach ebpf_prog : ebpf_progs
	ebpf_obj = custom_target(ebpf_prog + '.bpf.o',
		input: files(ebpf_prog + '.bpf.c'),
		output: ebpf_prog + '.bpf.o',
		depfile: ebpf_prog + '.bpf.o.d',
		env: ebpf_env,
		command: [ clang_bpf, ebpf_c_args,
			   '-MD', '-MF', '@DEPFILE@',
			   '-c', '@INPUT@', '-o', '@OUTPUT@' ])
	esdm_ebpf_skel_hdrs += custom_target(ebpf_prog + '.skel.h',
		input: ebpf_obj,
		output: ebpf_prog + '.skel.h',
		command: [ bpftool, 'gen', 'skeleton', '@INPUT@' ],
		capture: true)
endforeach

include_dirs_esdm_ebpf = include_directories('.')
