Name:       bluetooth-agent
Summary:    Bluetooth agent packages that support various external profiles
Version:    0.0.9
Release:    2
Group:      Network & Connectivity/Bluetooth
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	bluetooth-agent.manifest

BuildRequires:  pkgconfig(contacts-service2)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(msg-service)
BuildRequires:  pkgconfig(email-service)
BuildRequires:  pkgconfig(tapi)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  cmake

%description
Bluetooth agent packages that support various external profiles

%prep
%setup -q
cp %{SOURCE1001} .

%build
cmake . -DCMAKE_INSTALL_PREFIX=/usr

make VERBOSE=1

%install
rm -rf %{buildroot}
%make_install

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%{_bindir}/bluetooth-map-agent
#%{_bindir}/bluetooth-pb-agent
#%{_bindir}/bluetooth-hfp-agent
#%{_datadir}/dbus-1/system-services/org.bluez.pb_agent.service
%{_datadir}/dbus-1/services/org.bluez.map_agent.service
#%{_datadir}/dbus-1/system-services/org.bluez.hfp_agent.service
