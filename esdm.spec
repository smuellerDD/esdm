#
# spec file for package esdm
#
# Copyright (c) 2024 Stephan Mueller <smueller@chronox.de
#

Name:           esdm
Version:        1.1.2
Release:        1.1
Summary:        Entropy Source and DRNG Manager
License:        GPL-2.0 OR BSD-2-Clause
URL:            https://www.chronox.de/esdm
Source0:        https://www.chronox.de/%{name}/releases/%{version}/%{name}-%{version}.tar.xz
BuildRequires:  meson
BuildRequires:  gcc

%description
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

%package %{name}
Summary:        Entropy Source and DRNG Manager
Requires:       libjitterentropy
Requires:       libleancrypto
Requires:       libprotobuf

%description %{name}
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the ESDM server, the RPC client library and the CUSE
daemons.

%package -n %{name}-cuse
Summary:        Entropy Source and DRNG Manager CUSE device files
Requires:       fuse3
Requires:       %{name} = %{version}

%description -n %{name}-cuse
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the ESDM CUSE device files of /dev/random and
/dev/urandom as well as the files in /proc/sys/kernel/random/.

%package devel
Summary:        Entropy Source and DRNG Manager
Requires:       glibc-devel
Requires:       libjitterentropy-devel
Requires:       libleancrypto-devel
Requires:       libprotobuf-devel

%description devel
The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

This subpackage holds the development headers for the libraries.

%prep
%setup -q

%build
%meson -Dais2031=true -Dsp80090c=true -Dcrypto_backend=leancrypto -Dselinux=disabled
%meson_build

%check
%meson_test

%install
%meson_install

%post -n %{name}
/sbin/ldconfig
%systemd_post %{name}-server.service
%systemd_post %{name}-server-suspend.service
%systemd_post %{name}-server-resume.service

  if [ $1 -eq 1 ]; then
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl start %{name}-server
    /usr/bin/systemctl enable %{name}-server
    /usr/bin/systemctl enable %{name}-server-suspend
    /usr/bin/systemctl enable %{name}-server-resume
  fi
  if [ $1 -eq 2 ]; then
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl start %{name}-server
    /usr/bin/systemctl enable %{name}-server
    /usr/bin/systemctl enable %{name}-server-suspend
    /usr/bin/systemctl enable %{name}-server-resume
  fi

%post -n %{name}-cuse
%systemd_post %{name}-linux-compat.target

  if [ $1 -eq 1 ]; then
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl start %{name}-linux-compat.target
    /usr/bin/systemctl enable %{name}-linux-compat.target
  fi
  if [ $1 -eq 2 ]; then
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl start %{name}-linux-compat.target
    /usr/bin/systemctl enable %{name}-linux-compat.target
  fi

%preun -n %{name}
%systemd_preun %{name}-server.service
%systemd_preun %{name}-server-suspend.service
%systemd_preun %{name}-server-resume.service

%preun -n %{name}-cuse
%systemd_preun %{name}-linux-compat.target

%postun -n %{name} -p /sbin/ldconfig

%files -n %{name}
%license LICENSE LICENSE.bsd LICENSE.gplv2
%doc README.md README.usage.md
%{_libdir}/lib%{name}*.so*
%{_libdir}/pkgconfig/%{name}_*.pc
%{_libdir}/pkgconfig/%{name}-*.pc
%{_bindir}/esdm-server*
%{_unitdir}/esdm-server*

%files -n %{name}-cuse
%{_bindir}/esdm-cuse*
%{_bindir}/esdm-proc
%{_unitdir}/esdm-cuse*
%{_unitdir}/esdm-proc.service
%{_unitdir}/esdm-linux-compat.target

%files devel
%doc CHANGES.md
%{_includedir}/%{name}
