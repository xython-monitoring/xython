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
Github pipelines generates a debian package, so you can download it and install it via:
> dpkg -i xython-0-1.deb

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

# Architecture
All active tests are handled by celery workers.
Celery is a distributed tasks manager, this will permit to be scalable and/or ran tests on another host.
Probably handling client data will also be handled by celery.

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

# difference/improvment over xymon
The goal is to be 100% compatible with old Xymon storage BUT via an option, I will support some possible change.
Probably all options stated as deprecated in xymon will be not supported.
In the same time, all BB and hobbit compatibility will be removed probably.

* TLS client <-> server: I plan to add support to communicate over TLS between server and client
* compression of data files: all histlogs could be compressed saving disk space
* There are some inconsistency in xymon between timestamp (like used in storing hostdata) and full date (like histlogs).
  Furthermore, using full localized date is bad when sorting directory output and lead to timezone problems.
  Xython will propose a new storage using only timestamp.
* disk status show which rule matched the partition

# client
I dont work on changing the client for the moment.
My goal is to keep the client simple as it can be already now. (a simple sh | nc)
But having a version of it with TLS is planned in the future.

# Contact
You can contact me on IRC libera channel #xython
