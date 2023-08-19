Name: xython
Version: @VER@
Release: 1
Group: Networking/Daemons
URL: https://github.com/xython-monitoring/xython/
License: GPL
Source: xython-%{version}.tar.gz
Summary: Xython network monitor
BuildRoot: /tmp/xymon-root
# gcc and g++ are here to make cmake happy
BuildRequires: python3-devel cmake gcc g++

%global debug_package %{nil}

%description
Xython (previously known as Hobbit) is a system for monitoring 
your network servers and applications. This package contains 
the server side of the Xymon package.

%package client
Summary: Xython client reporting data to the Xython server
Group: Applications/System

%description client
This package contains a client for the Xymon (previously known
as Hobbit) monitor. Clients report data about the local system to 
the monitor, allowing it to check on the status of the system 
load, filesystem utilisation, processes that must be running etc.

%prep
rm -rf $RPM_BUILD_ROOT

%setup
	echo "=========================== setup"
#        ./configure

%build
	python3 setup.py build
	%cmake
	%cmake_build

%install
	python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
	%cmake_install
	mkdir -p $RPM_BUILD_ROOT/var/log/xython
	mkdir -p $RPM_BUILD_ROOT/etc/init.d/
	pwd
	ls -l
	cp debian/xython-client.xython-client.init $RPM_BUILD_ROOT/etc/init.d/xython-client
	cp debian/xython.xythond.init $RPM_BUILD_ROOT/etc/init.d/xythond
	mkdir -p $RPM_BUILD_ROOT/usr/bin/
	cp client/* $RPM_BUILD_ROOT/usr/bin/
#	mkdir -p $RPM_BUILD_ROOT/usr/bin
#	mkdir -p $RPM_BUILD_ROOT/etc/httpd/conf.d
#	mv $RPM_BUILD_ROOT/etc/xymon/xymon-apache.conf $RPM_BUILD_ROOT/etc/httpd/conf.d/
#	rmdir $RPM_BUILD_ROOT/usr/lib/xymon/client/tmp
#	cd $RPM_BUILD_ROOT/usr/lib/xymon/client && ln -sf /tmp tmp
#	rmdir $RPM_BUILD_ROOT/usr/lib/xymon/client/logs
#	cd $RPM_BUILD_ROOT/usr/lib/xymon/client && ln -sf ../../../../var/log/xymon logs
#	mv $RPM_BUILD_ROOT/usr/lib/xymon/client/etc/xymonclient.cfg /tmp/xymonclient.cfg.$$
#	cat /tmp/xymonclient.cfg.$$ | sed -e 's!^XYMSRV=.*!include /var/run/xymonclient-runtime.cfg!' | grep -v "^XYMSERVERS=" >$RPM_BUILD_ROOT/usr/lib/xymon/client/etc/xymonclient.cfg
#	rm /tmp/xymonclient.cfg.$$

%clean
rm -rf $RPM_BUILD_ROOT


%pre
id xython 1>/dev/null 2>&1
if [ $? -ne 0 ]
then
   groupadd xython || true
   useradd -g xython -c "Xython user" -d /usr/lib/xython xython
fi
#if [ -e /var/log/xymon/xymonlaunch.pid -a -x /etc/init.d/xymon ]
#then
#	/etc/init.d/xymon stop || true
#fi

#%pre client
#if [ -e /var/log/xymon/clientlaunch.pid -a -x /etc/init.d/xymon-client ]
#then
#	/etc/init.d/xymon-client stop || true
#fi


%post
chkconfig --add xythond

%post client
chkconfig --add xython-client


%preun
#if [ -e /var/log/xymon/xymonlaunch.pid -a -x /etc/init.d/xymon ]
#then
#	/etc/init.d/xythond stop || true
#fi
chkconfig --del xythond

%preun client
#if [ -e /var/log/xymon/clientlaunch.pid -a -x /etc/init.d/xymon-client ]
#then
#	/etc/init.d/xymon-client stop || true
#fi
chkconfig --del xython-client


%files
%attr(644, root, root) %config /etc/xython/*
#%attr(644, root, root) %config /etc/httpd/conf.d/xymon-apache.conf
%attr(755, root, root) %dir /etc/xython 
%attr(-, root, root) %dir /etc/xython/web
%attr(755, xython, xython) %dir /var/log/xython
%attr(755, root, root) /etc/init.d/xythond
%attr(-, root, root) /usr/bin/*
%attr(-, xython, xython) /var/lib/xython
%attr(755, root, root) /usr/lib/xython/cgi-bin/xythoncgi.py
%attr(750, root, xython) /usr/share/xython
%attr(-, root, root) /usr/lib/python3.9

%files client
%attr(-, root, root) /usr/bin/xython-client
%attr(-, root, root) /usr/bin/xython-client.sh
%attr(-, root, root) /usr/bin/xython-client-looper.sh
%attr(755, root, root) /etc/init.d/xython-client

