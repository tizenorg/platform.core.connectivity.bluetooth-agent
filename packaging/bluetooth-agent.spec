Name:       bluetooth-agent
Summary:    Bluetooth agent packages that support various external profiles
Version:    0.0.8
Release:    2
Group:      TO_BE/FILLED_IN
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(contacts-service2)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(msg-service)
BuildRequires:  pkgconfig(tapi)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  cmake

%description
Bluetooth agent packages that support various external profiles

%prep
%setup -q

%build
export CFLAGS+=" -fpie -fvisibility=hidden"
export LDFLAGS+=" -Wl,--rpath=/usr/lib -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"

cmake . -DCMAKE_INSTALL_PREFIX=/usr

make VERBOSE=1

%install
rm -rf %{buildroot}
%make_install

%files
%manifest bluetooth-agent.manifest
%defattr(-, root, root)
%{_bindir}/bluetooth-map-agent
%{_bindir}/bluetooth-pb-agent
%{_bindir}/bluetooth-hfp-agent
%{_datadir}/dbus-1/services/org.bluez.pb_agent.service
%{_datadir}/dbus-1/services/org.bluez.map_agent.service
%{_datadir}/dbus-1/services/org.bluez.hfp_agent.service
