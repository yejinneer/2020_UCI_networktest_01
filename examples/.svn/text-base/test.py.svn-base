#!/usr/bin/python3.2
import sys
from pycap import pycap
packet = pycap(interface="wlan0", count=1)
for data in packet:
    myCount = 0
    for i in data:
        sys.stdout.write(hex(i))
