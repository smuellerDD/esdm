#!/bin/bash

OPTIONS_DIS="
es_cpu
es_jent
es_kernel
es_sched
fips140
node
selinux
linux-devfiles
linux-getrandom
esdm-server
testmode
"

OPTIONS_EN="
es_cpu
es_jent
es_kernel
es_sched
fips140
node
selinux
esdm-server
linux-devfiles
linux-getrandom
testmode
"

init()
{
	for i in $OPTIONS_EN
	do
		meson configure build -D${i}=enabled
	done
}

exec_test()
{
	for i in $OPTIONS_DIS
	do
		echo "Disable option $i"
		meson configure build -D${i}=disabled

		meson compile -C build

		if [ $? -ne 0 ]
		then
			echo "Compile error"
			meson configure build
			exit 1
		fi
	done

	for i in $OPTIONS_EN
	do
		echo "Enable option $i"
		meson configure build -D${i}=enabled

		meson compile -C build

		if [ $? -ne 0 ]
		then
			echo "Compile error"
			meson configure build
			exit 1
		fi
	done
}

compile_test()
{
	meson compile -C build
	if [ $? -ne 0 ]
	then
		cho "Compile error"
		meson configure build
		exit 1
	fi
	
	init
	exec_test

	meson configure build -Ddrng_hash_drbg=disabled
	meson configure build -Ddrng_chacha20=enabled
	meson compile -C build
	if [ $? -ne 0 ]
	then
		cho "Compile error"
		meson configure build
		exit 1
	fi
}

rm -rf build
CC=gcc meson setup build
compile_test

rm -rf build
CC=clang meson setup build
compile_test
