#!/usr/bin/env python
# -*-mode: python; coding: iso-8859-1 -*-
#
# Copyright (c) 2002-2005 Cendio AB. All rights reserved.

import sys
import rpc
import mountclient
import socket
import os
import md5


class PartialMOUNTClient:
    def __init__(self):
        pass

    def addpackers(self):
        self.packer = mountclient.mountpacker.MOUNTPacker(self)
        self.unpacker = mountclient.mountpacker.MOUNTUnpacker(self, '')

    def mnt(self, dirpath):
        res = mountclient.mounttypes.mountres3(self)
        self.make_call(mountclient.mountconstants.MOUNTPROC_MNT,
                       dirpath, self.packer.pack_string, res.unpack)
        return res
    

class TCPMOUNTClient(PartialMOUNTClient, rpc.RawTCPClient):
    def __init__(self, host, port):
        rpc.RawTCPClient.__init__(self, host,
                                  mountclient.mountconstants.MOUNT_PROGRAM,
                                  mountclient.mountconstants.MOUNT_V3,
                                  port)
        PartialMOUNTClient.__init__(self)


class NFSOTPClient:
    def __init__(self, host, port):
        self.mountcl = TCPMOUNTClient(host, port)

    def getotp(self, password):
        res = self.mountcl.mnt("@getnonce")

        if res.fhs_status != mountclient.mountconstants.MNT3_OK:
            print >>sys.stderr, "Failed to get nonce:", mountclient.mountconstants.mountstat3_id[res.fhs_status]
            sys.exit(1)
        
        fhandle = res.mountinfo.fhandle
        digest = md5.new(fhandle + password).hexdigest()
        return digest


def usage():
    print >>sys.stderr, "Usage: nfsotpclient.py host[:port]"
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()

    fields = sys.argv[1].split(":")
    host = fields[0]
    del fields[0]
    if fields:
        port = int(fields[0])
    else:
        # No port specified, fetch from portmapper
        # FIXME
        print >>sys.stderr, "Portmapper support not yet implemented"
        sys.exit(1)

    cl = NFSOTPClient(host, port)
    import getpass
    password = getpass.getpass()
    
    print cl.getotp(password)
