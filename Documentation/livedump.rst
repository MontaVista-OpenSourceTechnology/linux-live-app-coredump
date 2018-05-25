.. SPDX-License-Identifier: GPL-2.0

==========================
Live Application Core Dump
==========================

:Author: Corey Minyard <minyard@mvista.com> / <minyard@acm.org>

Live application core dump, or livedump, provides the ability to take a
coredump of an application that is still running without killing the
application, or stopping it for very long.

Livedump works by performing a special fork of an application that
copies all the threads, without allowing any of the threads to run.
It does this in a PID namespace it creates so it can keep the
process/thread ids the same.  Once the fork is done, the original
application is free to run and the core dump is taken in the forked
application.

To enable this, enable CONFIG_LIVEDUMP in the kernel config.  If that
is enabled, every process will have a file named "livedump" in
/proc/<pid>.

To take a livedump, echo an empty string to /proc/<pid>/livedump, like::

   echo "" >/proc/1234/livedump

That process will take a core dump using the standard way the
application would core dump.  Since the core limit (ulimit -c) is
usually zero, that means that this won't do anything normally unless
the core limit of the application is set.

But all is not lost!  Livedump will let you override a number of
things, including the core limit, in the forked application.  You can
do this by putting it in the string sent to the livedump file, as::

  echo "core_limit=unlimited" >/proc/1234/livedump

Some things you can set:

  sched_prio=<n>
    Set the nice value for the forked process.  This is
    useful to lower the priority so that the coredump doesn't interfere
    with the rest of the system so much.

  io_prio=<n>
    Set the I/O priority, again useful for limiting the
    impact of the coredump on the rest of the system.

  oom_adj=<n>
    Sets the OOM adjustment (like /proc/<pid>/oom_adj) for
    the forked process.  This will let you allow the forked process to
    be killed first in an OOM situation.

  core_limit=<n>|unlimited
    Set the core limit in the forked process.
    It is a numerical value or "unlimited" as in "ulimit -c".

