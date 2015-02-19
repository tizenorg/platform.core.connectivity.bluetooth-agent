Name:       bluetooth-agent
Summary:    Bluetooth agent packages that support various external profiles
Version:    0.0.9
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz

Requires(post): sys-assert
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(bluetooth-api)
%if "%{?tizen_profile_name}" == "mobile"
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
%if "%{?tizen_profile_name}" == "wearable"
BuildRequires:  pkgconfig(alarm-service)
BuildRequires:  pkgconfig(capi-appfw-app-manager)
BuildRequires:  pkgconfig(capi-system-device)
%endif
BuildRequires:  cmake

%description
Bluetooth agent packages that support various external profiles

%prep
%setup -q

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

export CFLAGS="$CFLAGS -DTIZEN_TELEPHONY_ENABLED"

%if "%{?tizen_profile_name}" == "wearable"
export CFLAGS="$CFLAGS -DTIZEN_WEARABLE"
export CFLAGS="$CFLAGS -DTIZEN_SUPPORT_LUNAR_DEVICE"
%else
%endif

export CFLAGS+=" -fpie -DPBAP_SIM_ENABLE"

export CFLAGS+=" -fpie -fvisibility=hidden"
export LDFLAGS+=" -Wl,--rpath=/usr/lib -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"

cmake . -DCMAKE_INSTALL_PREFIX=/usr \
%if "%{?tizen_profile_name}" == "wearable"
	-DTIZEN_WEARABLE=1 \
%else
	-DTIZEN_WEARABLE=0 \
%endif
	-DTIZEN_TELEPHONY_ENABLED=1

make VERBOSE=1

%install
rm -rf %{buildroot}
%make_install

install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-agent

%files
%manifest bluetooth-agent.manifest
%defattr(-, root, root)
%if "%{?tizen_profile_name}" == "wearable"
%{_bindir}/bluetooth-hf-agent
%{_datadir}/dbus-1/services/org.bluez.hf_agent.service
%else
# _TEMP_ check and remove later
#%if "%{?tizen_profile_name}" == "mobile"
%{_bindir}/bluetooth-map-agent
%{_bindir}/bluetooth-pb-agent
%{_datadir}/dbus-1/services/org.bluez.pb_agent.service
%{_datadir}/dbus-1/services/org.bluez.map_agent.service
%{_datadir}/dbus-1/services/org.bluez.ag_agent.service
%{_bindir}/bluetooth-ag-agent
%attr(0666,-,-) /opt/var/lib/bluetooth/voice-recognition-blacklist
#%endif
%endif
%{_datadir}/license/bluetooth-agent
