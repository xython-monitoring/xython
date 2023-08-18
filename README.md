# xython is a complete rewrite of xymon in python3

# Project goals
* compatibility: I seek maximum compatibility with xymon, starting with message protocol
* performance/scalability: xython should be able to handle small and big infrastructure testing
* Security: using python will remove lot of problem due to using C (all string handling)
* Testing: the maximum of code should be tested via pytest

# Performance
Let see what I will have. For the moment I stick with one process to do all stuff (just for fun), let see when it will break.
But my will is to be able to support at least 2000 xymon client on one setup.

# Milestones

WARNING: I need to update milestones, there are a bit obsolete

I have already some planned milestone:
- 0.1: the version 0.1 will be when everything I use in my personnal setup will be handled.
This include blueing, purple, seeing history, main and nongreen HTMl page
Handling client hostdata (cpu disk inode memory ports procs) and related hosts.cfg checks
Handling some active tests (conn, smtp, imap, http, ssh)

- 0.2: the version 0.2 will be when everything I use in my work setup will be handled.
This include acking, rrd, page, group

- 0.3 Probably finishing handling remaing hostdata section (files, msgs)

# Running mode, How to tests
## Requirements/Installation

Xython require python3 and some python modules (requests, sqlite, celery)
The goal is to have the minimum in non-core modules and only modules availlable via official packaging (Debian/RedHat/gentoo)

## Testing xython

**STRONG WARNING: do not run xython against xymon data files, this is not tested enough.**

### package install
#### using the APT repository
First you need to addi xython repository (bookworm only for the moment)
Add in /etc/apt/sources.list.d/xython.list
> deb https://www.xython.fr/xython-mirror /

And add the GPG key from <https://www.xython.fr/pgp-key.public> with:
> apt-key add pgp-key.public

#### manual debian setup
Github pipelines generates a debian package, so you can download it and install it via:
> dpkg -i xython-0-1.deb

TIPS: you can find the zip of the package in the bottom of a github actions summary
or in <https://www.xython.fr/xython-mirror/amd64/>

#### other distro
I plan to support RPM in the future

### source install

> git clone <https://github.com/xython-monitoring/xython.git>

Create a virtualenv for xython
> virtualenv xython

> source xython/bin/activate

> pip install celery[redis] requests

> ./setup.py install

Copy xymon configuration into /etc/xython
> cp -a /etc/xymon/ /etc/xython/

And modify at least XYMONVAR, so that xython could not overwrite your xymon files.

## explanation of different modes:

Thoses mode are available with the -x parameter

* xythonmode 0: xython uses only xymon directories **THIS IS NOT TESTED/RECOMMANDED**
* xythonmode 1: xython reads configuration from xymon, but store new data in its own directories
* xythonmode 2: xython run standalone in its own directories

## You want to check if xython can handle your working setup
This start xython in read only mode, in this mode xython will read xymon state and generate its own web page
This is the only case were you could safely point XYMONVAR to xymon files.
> xythond --tload -x 0 -R

## You want to run a standalone xython

**You still need a xymon install for html/gifs files**

You need to create directories for xython (and ensure xython can write to them)
> mkdir /usr/xython /var/log/xython

Start xythond with:
> xythond --etcdir /etc/xython/ -D

Start the celery workers with:
> python3 -m celery -A xython worker --loglevel=INFO


## docker
An example of mini install via docker could be found in the docker directory.

## xython client
xython has a xymon compatible client done in pure shell script.
You can find it in the client directory.

The fake_client generate output.
The fake_client.sh use fake_client output and send it to a server via either netcat or openssl s_client.

The current client is not finished, I need a bit of work to finish it ( adding some command parameter and autoguess server/port)

## TLS server
TLS communication with the client is handled by xyhton-tlsd.
You need to have a working PKI (CA + key + cert).
The key and cert used by xython-tlsd could be configured by:
* setting XYTHON_TLS_KEY=path and XYTHON_TLS_CRT=path in $etcdir/xython.cfg
* giving path directly to xyhton-tlsd arguments (--tlskey/--tlscrt)

TODO: TLS server is still a PoC which simply works, I need to bench it.

TODO: authentification of client will be done later

# Architecture
All active tests are handled by celery workers.
Celery is a distributed tasks manager, this will permit to be scalable and/or ran tests on another host.
Probably handling client data will also be handled by celery.

For clustering, I will work on using a rabbitMQ cluster to see if it is doable.

# clustering
For replacing the shared memory of xymon, a rabbitmq message queuing is used.
The usage of it is for the moment optionnal.

xython-nshow is an example of using it for displaying a ncurses overview.

Example of setupping the rabbitMQ xython user:
> rabbitmqctl add_user xython "password"

> rabbitmqctl set_permissions -p "/" "xython" ".*" ".*" ".*"


# equivalence
* xymonnet is replaced by xython_test on the celery cluster
* xymon_channel: xymon_channel could be replace by either a simple tool which ask xythond for recent change or the use of a rabbitMQ cluster
* xymongen: embedded in xythond for the moment
<!--
# Feature matrix
TODO
<table>
<tr>
<td>compoments</td>
<td>what</td>
<td>status</td>
<td>milestone</td>
<td>comment</td>
</tr>

<tr>
<td>hostdata</td>
<td>cpu</td>
<td>IN PROGRESS</td>
<td>0.1</td>
<td>Remains clock drift</td>
</tr>

<tr>
<td>hostdata</td>
<td>disk</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>hostdata</td>
<td>memory</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>hostdata</td>
<td>inode</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>hostdata</td>
<td>msgs</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>hostdata</td>
<td>procs</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>protocol</td>
<td>status</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>protocol</td>
<td>blue</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>protocol</td>
<td>ack</td>
<td>TODO</td>
<td>0.2</td>
</tr>

<tr>
<td>protocol</td>
<td>drop</td>
<td>TODO</td>
<td>0.1</td>
</tr>

<tr>
<td>status</td>
<td>flapping</td>
<td>TODO</td>
<td>0.1</td>
</tr>

<tr>
<td>status</td>
<td>class</td>
<td>TODO</td>
<td>0.2</td>
</tr>

<tr>
<td>net tests</td>
<td>conn</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>net tests</td>
<td>smtp</td>
<td>TODO</td>
<td>0.1</td>
</tr>

<tr>
<td>net tests</td>
<td>imap</td>
<td>TODO</td>
<td>0.1</td>
</tr>

<tr>
<td>net tests</td>
<td>http</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>net tests</td>
<td>ssh</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>gen page</td>
<td>main view</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>gen page</td>
<td>nongreen</td>
<td>IN PROGRESS</td>
<td>0.1</td>
</tr>

<tr>
<td>gen page</td>
<td>group</td>
<td>TODO</td>
<td>0.2</td>
</tr>

</table>
TODO: fill all hosts.cfg manpage in this table
-->

# difference/improvment over xymon
The goal is to be 100% compatible with old Xymon storage BUT via an option, I will support some possible change.
Probably all options stated as deprecated in xymon will be not supported.
In the same time, all BB and hobbit compatibility will be removed probably.

* compression of data files: all histlogs could be compressed saving disk space
* There are some inconsistency in xymon between timestamp (like used in storing hostdata) and full date (like histlogs).
  Furthermore, using full localized date is bad when sorting directory output and lead to timezone problems.
  Xython will propose a new storage using only timestamp.
* disk status show which rule matched the partition
* TODO: permit to hide acked tests in nongreen page
* Add more "standard" tests to xymon client (ntpd, smart, lvm, sensors for example)
* TLS communication between client and server is supported as a PoC (until I finish deploy client)
* IPV6 communication between client and server is supported

# GUI
## acks
you could ack directly from a status page

# client
My goal is to keep the client simple as it can be already now. (a simple sh | nc)
But having a version of it with TLS is currently worked.

## lm-sensors
The xymon client provided by xython support now reporting lm-sensors

## planned
smart
megacli
ntpd + rtc
kernel log / dmesg
ip route (to replace obsolete netstat), already reported by client, but xythond need to check them
ss (to replace obsolete netstat), already reported by client, but xythond need to check them

# TODO
This is a uncomplete

* fuzz xython
* re-bench xython
* the overview could be generated by the CGI (instead of generated every x seconds/minutes)
* github/test: client + server in docker
* github/test: test IPV6
* github/test: test TLS

# List of xython install path

TODO

* /etc/xython: xython specific configuration (mostly xython.cfg)
* /usr/share/xython/:   webpage graphic

# Contact
You can contact me (nick montjoie) on IRC libera channel #xython
