%define _usrlibdir /usr/lib

Name:       bluetooth-agent
Summary:    Bluetooth agent packages that support various external profiles
Version:    0.1.0
Release:    1
Group:      Network & Connectivity/Bluetooth
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	bluetooth-agent.manifest

Requires(post): sys-assert
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(bluetooth-api)
%if "%{?profile}" == "wearable"
BuildRequires:  pkgconfig(alarm-service)
BuildRequires:  pkgconfig(capi-appfw-app-manager)
BuildRequires:  pkgconfig(capi-system-device)
%else
BuildRequires:  pkgconfig(contacts-service2)
BuildRequires:  pkgconfig(msg-service)
%endif
BuildRequires:  pkgconfig(capi-system-info)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(tapi)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  pkgconfig(capi-media-image-util)
BuildRequires:  pkgconfig(libexif)
BuildRequires:  cmake

%description
Bluetooth agent packages that support various external profiles

%prep
%setup -q
cp %{SOURCE1001} .

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export CFLAGS="$CFLAGS -DTIZEN_MEDIA_ENHANCE"
export CFLAGS="$CFLAGS -DTIZEN_BT_HFP_AG_ENABLE"

%if "%{?profile}" == "wearable"
export CFLAGS="$CFLAGS -DTIZEN_WEARABLE"
export CFLAGS="$CFLAGS -DTIZEN_SUPPORT_LUNAR_DEVICE"
%else
export CFLAGS="$CFLAGS -DTIZEN_KIRAN"
%endif

export CFLAGS+=" -fpie -DPBAP_SIM_ENABLE"

export CFLAGS+=" -fpie -fvisibility=hidden"
export LDFLAGS+=" -Wl,--rpath=/usr/lib -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"

cmake . -DCMAKE_INSTALL_PREFIX=/usr \
%if "%{?profile}" == "wearable"
        -DTIZEN_WEARABLE=1 \
%else
        -DTIZEN_WEARABLE=0 \
%endif
        -DTIZEN_BT_HFP_AG_ENABLE=1

make VERBOSE=1

%install
rm -rf %{buildroot}
%make_install

install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-agent
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
%if "%{?profile}" != "wearable"
install -m 0644 packaging/bluetooth-ag-agent.service %{buildroot}%{_unitdir}/
ln -s ../bluetooth-ag-agent.service %{buildroot}%{_unitdir}/multi-user.target.wants/bluetooth-ag-agent.service
%endif

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%if "%{?profile}" == "wearable"
%{_bindir}/bluetooth-hf-agent
%{_datadir}/dbus-1/system-services/org.bluez.hf_agent.service
%else
%{_bindir}/bluetooth-ag-agent
%{_bindir}/bluetooth-map-agent
%{_bindir}/bluetooth-pb-agent
%{_datadir}/dbus-1/system-services/org.bluez.pb_agent.service
%{_datadir}/dbus-1/system-services/org.bluez.map_agent.service
%{_datadir}/dbus-1/system-services/org.bluez.ag_agent.service
%{_usrlibdir}/systemd/system/bluetooth-ag-agent.service
%{_usrlibdir}/systemd/system/multi-user.target.wants/bluetooth-ag-agent.service
%attr(0666,-,-) /opt/var/lib/bluetooth/voice-recognition-blacklist
%endif
%{_datadir}/license/bluetooth-agent
%{_sysconfdir}/dbus-1/system.d/bluetooth-ag-agent.conf
