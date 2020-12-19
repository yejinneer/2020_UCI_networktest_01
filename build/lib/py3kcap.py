#!/usr/bin/env python3.2

import ctypes,sys
from ctypes.util import find_library
from pcap_struct import *
from pcap_func import *

class pycap:
    
    def __init__(self, interface=None,filter=None,count=0):
        self.interface = interface.encode('ascii')
        self.filter = filter
        self.count = count
        self.counter = 0
        self.optimize = ctypes.c_int(1)
        self.mask = ctypes.c_uint(0xffffffff)
        self.net = ctypes.c_uint()
        self.snaplen = ctypes.c_int(1500)
        self.to_ms = ctypes.c_int(100000)
        self.promisc = ctypes.c_int(1)
        self.buf = ctypes.c_char_p(filter)
        self.errbuf = ctypes.create_string_buffer(256)
        self.packetdata = ctypes.POINTER(ctypes.c_ubyte*65536)()
        self.pkthdrPointer = ctypes.POINTER(pcap_pkthdr)()
        
        
        
        # if no interface defined then try to look it up 
        if(self.interface==None):
            self.interface = pcap_lookupdev(self.errbuf)
            if(dev):
             print("{0} is the default interface".format(self.interface))
            else:
                print("Error unable to determine default interface -> {0}".format(self.errbuf))
        
        #establish handle 
        self.handle = pcap_open_live(self.interface,self.snaplen,self.promisc,self.to_ms,self.errbuf)

        if not self.handle:
            print("Error unable to open session : {0}".format(self.errbuf.value))
            sys.exit(0)
            
        # Install filter if user set one
        if((pcap_compile(self.handle,ctypes.byref(program),self.buf,self.optimize,self.mask) == -1) and filter):
        # this requires we call pcap_geterr() to get the error
            err = pcap_geterr(self.handle)
            print("Error could not compile bpf filter because {0}".format(err))
            sys.exit(0)
        else:
            if(pcap_setfilter(self.handle,ctypes.byref(program)) == -1):
                err = pcap_geterr(self.handle)
                print("pcap_setfilter error: {0}".format(err))
                sys.exit(0)
    def __iter__(self):
        return self
    def __next__(self):
        #pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,const u_char **pkt_data)
        if(pcap_next_ex(self.handle,ctypes.byref(self.pkthdrPointer),ctypes.byref(self.packetdata))<0):
           err = pcap_geterr(self.handle)
           print("pcap_next_ex error: {0}".format(err))
           raise StopIteration
        else:
            if(self.count>0):
                while(self.counter<self.count):
                    self.counter = self.counter + 1 
                    myPacket = bytes(self.packetdata.contents)
                    return  myPacket[:self.pkthdrPointer.contents.len]
                raise StopIteration
            else:
                myPacket = bytes(self.packetdata.contents)
                return myPacket[:self.pkthdrPointer.contents.len]
                
