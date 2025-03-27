# UNFS3, a User-Space NFSv3 Server

(C) 2003-2025, various authors

UNFS3 is a user-space implementation of the NFSv3 server
specification.

UNFS3 supports all NFSv3 procedures with the exception of the
READDIRPLUS procedure. It tries to provide as much information
to NFS clients as possible, within the limits possible from
user-space.

See the unfsd(8) manpage for restrictions imposed on NFS
operations (section RESTRICTIONS) and for possible races
with local file system activity (section BUGS).

It is not possible to export to netgroups or wildcard hostnames
via /etc/exports, all other addressing methods should work. The
following options are recognized in the exports file: ro, rw,
root_squash, all_squash, no_root_squash, no_all_squash. If
other options are present, they are ignored.

UNFS3 can be used to (re-)export part of an AFS network filesystem.
Because AFS does not simulate inodes particularly well, configuring the
source with --enable-afs is recommended in this scenario.

Cluster extensions compatible to the older ClusterNFS project
are supported when the source is configured with --enable-cluster.


## Supported systems

unfs3 is developed and tested on Linux, but should also compile
and run on other Unix systems. In the past, versions of unfs3
have been successfully tested on NetBSD, FreeBSD, Solaris, AIX,
Irix, and Mac OS X. There is also some support for running on
Windows, see doc/README.win for details.

Releases are tested by trying to compile them on Linux, macOS and
Windows.

If unfs3 doesn't build or work on a Unix system, a problem
report is appreciated.


## Building from source

You will need gcc, lex (flex), yacc (bison), and libtirpc to compile
UNFS3.

    ./bootstrap   # (only when building from git)
    ./configure
    make
    make install

Please read the manpage for information about command-line
options.

    man 8 unfsd

If you decide to modify the code yourself, you can run

    make dep

to append dependency information to the Makefile, so that make
knows which files depend on each other and recompiles all the
necessary files on changes.
