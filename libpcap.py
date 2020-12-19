#!/usr/bin/env python3.2

import ctypes,sys
from ctypes.util import find_library
from pcap_struct import *
from pcap_func import *

pcap = None

if(find_library("libpcap") == None):
    print("We are here!")
    pcap = ctypes.cdll.LoadLibrary("libpcap.so")
else:
    pcap = ctypes.cdll.LoadLibrary(find_library("libpcap"))


# prepare args
snaplen = ctypes.c_int(1500)

#buf = ctypes.c_char_p(filter)
optimize = ctypes.c_int(1)
mask = ctypes.c_uint()
net = ctypes.c_uint()
to_ms = ctypes.c_int(100000)
promisc = ctypes.c_int(1)
filter = b"port 80"
buf = ctypes.c_char_p(filter)
errbuf = ctypes.create_string_buffer(256)

#check for default lookup device
dev = pcap_lookupdev(errbuf)
dev = b'wlan0'

if(dev):
    print("{0} is the default interface".format(dev))
else:
    print("Was not able to find default interface")
    

if(pcap_lookupnet(dev,ctypes.byref(net),ctypes.byref(mask),errbuf) == -1):
    print("Error could not get netmask for device {0}".format(errbuf))
    sys.exit(0)
else:
    print("Got Required netmask")

handle = pcap_open_live(dev,snaplen,promisc,to_ms,errbuf)

if not handle:
    print("Error unable to open session : {0}".format(errbuf.value))
    sys.exit(0)
else:
    print("Pcap open live worked!")

if(pcap_compile(handle,ctypes.byref(program),buf,optimize,mask) == -1):
    # this requires we call pcap_geterr() to get the error
    err = pcap_geterr(handle)
    print("Error could not compile bpf filter because {0}".format(err))
else:
    print("Filter Compiled!")
if(pcap_setfilter(handle,ctypes.byref(program)) == -1):
    err = pcap_geterr(handle)
    print("pcap_setfilter error: {0}".format(err))
    print("Error couldn't install filter {0}".format(errbuf.value))
    sys.exit(0)
else:
    print("Filter installed!")


# Something for user data
class User(ctypes.Structure):
    _fields_ = [
        ('one',ctypes.c_uint),
        ('two',ctypes.c_uint),
        ('three',ctypes.c_char_p)]
#void got_packet(u_char *args, const struct pcap_pkthdr *header,
#	    const u_char *packet)
CALLBACK = ctypes.CFUNCTYPE(None,ctypes.POINTER(User),ctypes.POINTER(pcap_pkthdr),ctypes.POINTER(ctypes.c_ubyte*65536))

def pkthandler(param,pkthdr,packet):
    print("In callback:")
    print("pkthdr[0:7]:",pkthdr.contents.len)
    print(param.contents.three)
    print(pkthdr.contents.tv_sec,pkthdr.contents.caplen,pkthdr.contents.len)
    print(packet.contents[:10])
    print()




got_packet=CALLBACK(pkthandler)
user = User(1,2,b"hello")

try:
    if(pcap_loop(handle,ctypes.c_int(3), got_packet,ctypes.byref(user)) == -1):
        err = pcap_geterr(handle)
        print("pcap_loop error: {0}".format(err))
except KeyboardInterrupt:
    pcap_close(handle)
