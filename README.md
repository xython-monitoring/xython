# xython is a complete rewrite of xymon in python3

## Project goals

* compatibility: I seek maximum compatibility with xymon, starting with message protocol
* performance/scalability: xython should be able to handle small and big infrastructure testing
* Security: using python will remove lot of problem due to using C (all string handling)
* Testing: the maximum of code should be tested via pytest

## Performance

Let see what I will have. For the moment I stick with one process to do all stuff (just for fun), let see when it will break.
But my will is to be able to support at least 2000 xymon client on one setup.

There are 2 important metrics to measure xython performance

* time to generate the normal and nongreen view (TODO: add current numbers)
* number of handled network status per second (TODO: add current numbers)

## Milestones

WARNING: I need to update milestones, there are a bit obsolete

I have already some planned milestone:

* 0.1: the version 0.1 will be when everything I use in my personnal setup will be handled.
  This include blueing, purple, seeing history, main and nongreen HTMl page
  Handling client hostdata (cpu disk inode memory ports procs) and related hosts.cfg checks
  Handling some active tests (conn, smtp, imap, http, ssh)

* 0.2: the version 0.2 will work on everything I use in my work setup will be handled.
  This include acking, RRD, page, group and a basic bot alerting

* 0.3 Probably finishing handling remaing hostdata section (files, msgs)

* 0.4 alerting

## Running mode, How to tests

### Requirements/Installation

Xython require python3 and some python modules (requests, sqlite, celery)
The goal is to have the minimum in non-core modules and only modules availlable via official packaging (Debian/RedHat/gentoo)

### Testing xython

**STRONG WARNING: do not run xython against xymon data files, this is not tested enough.**

#### package install

##### using the APT repository

First you need to add xython repository
Add in /etc/apt/sources.list.d/xython.list
> deb `https://www.xython.fr/mirror/bookworm` /

For bullseye simply replace bookworm by bullseye in the URL.

And add the GPG key from <https://www.xython.fr/pgp-key.public> with:
> apt-get install gnupg
> wget `https://www.xython.fr/pgp-key.public`
> gpg -o /etc/apt/trusted.gpg.d/xython.gpg --dearmour pgp-key.public

Or the old way:
> apt-key add pgp-key.public

Then install packages
> apt-get install xython apache2 redis-server

Enable necessary apache modules
> a2enmod cgi
> a2enconf xython
> systemctl restart apache2

Start services
> /etc/init.d/redis-server start
> /etc/init.d/xython start

<!--
#### manual debian setup
Github pipelines generates a debian package, so you can download it and install it via:
> dpkg -i xython-0-1.deb

TIPS: you can find the zip of the package in the bottom of a github actions summary
or in <https://www.xython.fr/xython-mirror/amd64/>
-->

##### Gentoo

The ebuild for gentoo could be found at <https://github.com/montjoie/montjoiegentooportage.git>

##### BSD

I plan to support freeBSD, openBSD and netBSD

##### client install on currently non-packaged distro (BSD, OPNsense, openWRT)

The easiest way to have client on such host is to use the tssh way, the server will execute client over SSH (See man page)

In case you do not want that:

* You have just to copy client/* in /usr/bin/
* Recreate /etc/xython with etc/xython-client.cfg
* Run xython-client.sh via a cron

TODO test openWRT

##### other RPM distro

For RPM packaging, I target fedora 39 and rockylinux9. (Please ask for more if needed)

For xython server, python3-celery is missing in thoses OS and also in EPEL:9, so the situation was blocked.
We need to wait on <https://bugzilla.redhat.com/show_bug.cgi?id=2032543>
But I have packaged missing ones in the xython repository.

> Add <https://www.xython.fr/mirror/xython.repo> in /etc/yum.repos.d/
You need to edit it and replace __OSNAME__ by either fedora39 or rockylinux9

One package needed is present in EPEL repository
> yum install epel-release

Then you just have to
> yum install xython
or for the client only
> yum install xython-client

#### source install

> git clone <https://github.com/xython-monitoring/xython.git>

Create a virtualenv for xython
> virtualenv xython
> source xython/bin/activate
> pip install celery[redis] requests
> ./setup.py install

Copy xymon configuration into /etc/xython
> cp -a /etc/xymon/ /etc/xython/

And modify at least XYMONVAR, so that xython could not overwrite your xymon files.

### explanation of different modes

Thoses mode are available with the -x parameter

* xythonmode 0: xython uses only xymon directories **THIS IS NOT TESTED/RECOMMANDED**
* xythonmode 1: xython reads configuration from xymon, but store new data in its own directories
* xythonmode 2: xython run standalone in its own directories

### You want to check if xython can handle your working setup

This start xython in read only mode, in this mode xython will read xymon state and generate its own web page
This is the only case were you could safely point XYMONVAR to xymon files.
> xythond --tload -x 0 -R

### You want to run a standalone xython

Simply ran xython-celery, xythond and xython client either via their init files or their systemd unit.

> /etc/init.d/xython-celery start
> /etc/init.d/xythond start
> /etc/init.d/xython-client start
> systemctl start xython-celery
> systemctl start xythond
> systemctl start xython-client

### docker

An example of mini install via docker could be found in the docker directory.

### xython client

xython has a xymon compatible client done in pure shell script.
You can find it in the client directory.

The xython-client generate output.
The xython-client.sh use xython-client output and send it to a server via either netcat or openssl s_client.

The configuration for xython-client is done in /etc/xython/xython-client.cfg
By default xython-client will try to find server according to xymon configuration.
The configuration directive in /etc/xython/xython-client.cfg take priority against xymon configuration.

You can change the xymon fqdn and port via XYMSRV and XYTHON_PORT.

### TLS communication between server and client

Xython allow to have a secure communication between client and server.

You have 2 choices:

#### Use HTTPS proxy

You can enable push of client data via the xython HTTP proxy by setting USE_TLS=1
If you use a custom CA (or self-signed certificate), dont forget to set CAFILE

#### Use xythond

TLS communication with the client is handled by xythond.
You need to have a working PKI (CA + key + cert).
The key and cert used by xythond could be configured by:

* setting XYTHON_TLS_KEY=path and XYTHON_TLS_CRT=path in $etcdir/xython.cfg
* giving path directly to xythond arguments (--tlskey/--tlscrt)

TODO: TLS server is still a PoC which simply works, I need to bench it.

You can generate a self signed certificate with:
> openssl req -x509 -newkey rsa:4096 -keyout /etc/xython/xython.key -out /etc/xython/xython.crt -sha256 -days 3650 -nodes -subj "/C=FR/ST=France/L=Paris/O=xython/OU=tests/CN=xython"

TODO: authentification of client will be done later

You can enable TLS for client by setting USE_TLS=1 and set TLS_MODE="openssl"
You will need to change port to the one used by xythond.
You will need also so set the CAfile path.

## Architecture

All active tests are handled by celery workers.
Celery is a distributed tasks manager, this will permit to be scalable and/or ran tests on another host.
Probably handling client data will also be handled by celery.

For clustering, I will work on using a rabbitMQ cluster to see if it is doable.

## clustering

For replacing the shared memory of xymon, a rabbitmq message queuing is used.
The usage of it is for the moment optionnal.

xython-nshow is an example of using it for displaying a ncurses overview.

Example of setupping the rabbitMQ xython user:
> rabbitmqctl add_user xython "password"
> rabbitmqctl set_permissions -p "/" "xython" ".*" ".*" ".*"

## equivalence

* xymonnet is replaced by xython_test on the celery cluster
* xymon_channel: xymon_channel could be replace by either a simple tool which ask xythond for recent change or the use of a rabbitMQ cluster
* xymongen: embedded in xythond for the moment

## difference/improvment over xymon

The goal is to be 100% compatible with old Xymon storage BUT via an option, I will support some possible change.
Probably all options stated as deprecated in xymon will be not supported.
In the same time, all BB and hobbit compatibility will be removed probably.

### Changes in server (vs xymon)

* There are some inconsistency in xymon between timestamp (like used in storing hostdata) and full date (like histlogs).
  Furthermore, using full localized date is bad when sorting directory output and lead to timezone problems.
  Xython will propose a new storage using only timestamp.
* disk status show which rule matched the partition
* TLS communication between client and server is supported as a PoC (until I finish deploy client)
* IPV6 communication between client and server is supported
* you could ack and disable directly from a status page
* you can choose which ipvX address to ping ( you can choose both with conn:ipv4:ipv6
* Added a verify= option to http test to allow using custom CA or disabling testing certificate
* Added SNMP support, you can simulate a client by gathering information via SNMP
* Custom SNMP graphing and reporting
* deprecating httpstatus, xython way is to add httpcode=xxx to a http URL
* deprecating cont, xython way is to add cont=xxx to a http URL
* permit to ack/blue directly from status page
* Adding "live view "of main/non-green page (live mean no-pre-generated)

### Changes in client

* The xython client support now reporting lm-sensors
* The xython client reports dmesg
* ip route (to replace obsolete netstat), already reported by client, but xythond need to check them
* ss (to replace obsolete netstat), already reported by client, but xythond need to check them
* The xython client can report either via direct TLS or via HTTPS

### Planned changes in server

* compression of data files: all histlogs could be compressed saving disk space
* permit to hide acked tests in nongreen page

### Planned changes in client

* Add more "standard" tests to xymon client (ntpd, smart, lvm, sensors for example)
* smart
* megacli
* ntpd + rtc
* docker ps
* interface link report (ethtool)

## Migrating from xymon

TODO create a script from converting a xymon install to a xython install

* checking consistancy of data
* moving from xymon datadir to /var/lib/xython
* compressing files

## TODO

This is a raw uncomplete list

* fuzz xython
* re-bench xython
* github/test: client + server in docker
* github/test: test IPV6
* github/test: test TLS
* RPM packages (near done, see comment on other distro)
* github/test: rpm
* Add manpage
* Add html manpage
* use PINGCOLUMN
* add conn by default on hosts
* rename pgp public key
* ACL on commands
* compressed messages/status
* handle docker ps like proc column
* handle WMI for fake windows client
* OpenVAS integration
* modelize depencies between hosts
* do nslookup via ssh
* disk: permit to set limit on Mb/Gb instead of percentage

## List of xython install path (FHS)

TODO

* /etc/xython               xython specific configuratio
* /etc/xython/snmpd.d       SNMP custom graph directory
* /usr/share/xython/        webpage graphic
* /var/lib/xython           base directory for xython data
* /var/lib/xython/acks      acknowledges are store here
* /var/lib/xython/hist      xymon like hist
* /var/lib/xython/hostdata  xymon like hostdata
* /var/lib/xython/rrd       base directory for RRD
* /var/lib/xython/state     xython store current state of all status in this directory, used when starting xython to restore all status to a sane state
* /run/xython/              Directory containing the xython UNIX socket file. Used for communication with apache/TLSd/xython-snmpd
* /run/xython-client/       Directory for storing temporary files for the client

## Documentation

You could see online documentation at <https://www.xython.fr/hosts.cfg.5.html>

## Contact

You can contact me (nick montjoie) on IRC libera channel #xython
