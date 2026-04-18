#
# spec file for package esdm
#
# Copyright (c) 2024 - 2026 Stephan Mueller <smueller@chronox.de
#

Name:           esdm
Version:        1.2.3
Release:        1.1
Summary:        Entropy Source and DRNG Manager
License:        GPL-2.0 OR BSD-2-Clause
URL:            https://www.chronox.de/esdm
Source0:        https://www.chronox.de/%{name}/releases/%{version}/%{name}-%{version}.tar.xz
BuildRequires:  meson
BuildRequires:  gcc
BuildRequires:  fuse3
BuildRequires:  fuse3-devel
BuildRequires:  leancrypto-devel
BuildRequires:  libjitterentropy3
BuildRequires:  libprotobuf-c-devel
BuildRequires:  pkgconfig
BuildRequires:  libopenssl-devel
BuildRequires:  gcc-c++
BuildRequires:  meson
BuildRequires:  ninja
BuildRequires:  systemd-rpm-macros

%description
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

%package %{name}
Summary:        Entropy Source and DRNG Manager
Requires:       libjitterentropy
Requires:       libleancrypto1
Requires:       libprotobuf
Requires:       systemd

%description %{name}
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the ESDM server, and the RPC client library allowing
users to interact with the ESDM via its APIs.

%package devel
Summary:        Entropy Source and DRNG Manager
Requires:       glibc-devel
Requires:       libjitterentropy3
Requires:       leancrypto-devel
Requires:       libprotobuf-c-devel

%description devel
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the development headers for the libraries.

%package devel-static
Summary:        Static library for ESDM
Requires:       %{name}-devel = %{version}
Provides:       %{name}-devel:%{_libdir}/lib%{name}_rpc_client.a

%description devel-static
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage contains the static version of the library
used for development.

%package -n %{name}-cuse
Summary:        Entropy Source and DRNG Manager CUSE device files
Requires:       fuse3
Requires:       systemd
Requires:       %{name} = %{version}

%description -n %{name}-cuse
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the ESDM CUSE device files of /dev/random and
/dev/urandom as well as the files in /proc/sys/kernel/random/. Therefore, this
package turns the ESDM in an API and ABI drop-in replacement of the Linux
/dev/random device for user space.

%package -n %{name}-openssl
Summary:        Entropy Source and DRNG Manager OpenSSL RAND Provider
Requires:       %{name} = %{version}

%description -n %{name}-openssl
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the OpenSSL 3 RAND provider

%prep
%setup -q

%build
# No SELinux support
%meson -Dais2031=true -Dsp80090c=true -Dcrypto_backend=leancrypto -Dselinux=disabled -Dopenssl-rand-provider=enabled
%meson_build

%check
%meson_test

%install
%meson_install

%pre -n %{name}
%service_add_pre %{name}-server.service
%service_add_pre %{name}-server-suspend.service
%service_add_pre %{name}-server-resume.service
%service_add_pre %{name}-kernel-seeder.service
%service_add_pre %{name}-wait-until-fully-seeded.service

%pre -n %{name}-cuse
%service_add_pre %{name}-linux-compat.target

%post -n %{name}
/sbin/ldconfig
%service_add_post %{name}-server.service
%service_add_post %{name}-server-suspend.service
%service_add_post %{name}-server-resume.service
%service_add_post %{name}-kernel-seeder.service
%service_add_post %{name}-wait-until-fully-seeded.service

#   if [ $1 -eq 1 ]; then
#     %{_bindir}/systemctl daemon-reload
#     %{_bindir}/systemctl start %{name}-server
#     %{_bindir}/systemctl enable %{name}-serversys
#     %{_bindir}/systemctl enable %{name}-server-suspend
#     %{_bindir}/systemctl enable %{name}-server-resume
#     %{_bindir}/systemctl enable %{name}-kernel-seeder
#     %{_bindir}/systemctl enable %{name}-wait-until-fully-seeded
#   fi
#   if [ $1 -eq 2 ]; then
#     %{_bindir}/systemctl daemon-reload
#     %{_bindir}/systemctl start %{name}-server
#     %{_bindir}/systemctl enable %{name}-server
#     %{_bindir}/systemctl enable %{name}-server-suspend
#     %{_bindir}/systemctl enable %{name}-server-resume
#     %{_bindir}/systemctl enable %{name}-kernel-seeder
#     %{_bindir}/systemctl enable %{name}-wait-until-fully-seeded
#   fi

%post -n %{name}-cuse
%service_add_post %{name}-linux-compat.target

#   if [ $1 -eq 1 ]; then
#     %{_bindir}/systemctl daemon-reload
#     %{_bindir}/systemctl start %{name}-linux-compat.target
#     %{_bindir}/systemctl enable %{name}-linux-compat.target
#   fi
#   if [ $1 -eq 2 ]; then
#     %{_bindir}/systemctl daemon-reload
#     %{_bindir}/systemctl start %{name}-linux-compat.target
#     %{_bindir}/systemctl enable %{name}-linux-compat.target
#   fi

%post -n %{name}-openssl -p /sbin/ldconfig

%preun -n %{name}
%service_del_preun %{name}-server.service
%service_del_preun %{name}-server-suspend.service
%service_del_preun %{name}-server-resume.service
%service_del_preun %{name}-kernel-seeder.service
%service_del_preun %{name}-wait-until-fully-seeded.service

%preun -n %{name}-cuse
%service_del_preun %{name}-linux-compat.target

%postun -n %{name}
/sbin/ldconfig
%service_del_postun %{name}-server.service
%service_del_postun %{name}-server-suspend.service
%service_del_postun %{name}-server-resume.service
%service_del_postun %{name}-kernel-seeder.service
%service_del_postun %{name}-wait-until-fully-seeded.service

%postun -n %{name}-cuse
%service_del_postun %{name}-linux-compat.target

%postun -n %{name}-openssl -p /sbin/ldconfig

%files -n %{name}
%license LICENSE LICENSE.bsd LICENSE.gplv2
%doc README.md README.usage.md
%{_libdir}/lib%{name}_aux*.so*
%{_libdir}/lib%{name}-getrandom*.so*
%{_libdir}/lib%{name}_rpc_client*.so*
%{_libdir}/lib%{name}.so*
%{_libdir}/pkgconfig/%{name}_*.pc
%{_libdir}/pkgconfig/%{name}-*.pc
%{_bindir}/esdm-server*
%{_bindir}/esdm-kernel-seeder
%{_bindir}/esdm-tool
%{_unitdir}/esdm-server*
%{_unitdir}/esdm-kernel-seeder*
%{_unitdir}/esdm-wait-until-fully-seeded*

%files -n %{name}-cuse
%{_bindir}/esdm-cuse*
%{_bindir}/esdm-proc
%{_unitdir}/esdm-cuse*
%{_unitdir}/esdm-proc.service
%{_unitdir}/esdm-linux-compat.target

%files -n %{name}-openssl
%{_libdir}/lib%{name}-rng-provider*.so*
%{_libdir}/lib%{name}-seed-src-provider*.so*

%files devel
%doc CHANGES.md
%{_includedir}/%{name}

%files devel-static
%{_libdir}/lib%{name}_aux_client.a
%{_libdir}/lib%{name}-getrandom.a
%{_libdir}/lib%{name}_rpc_client.a
