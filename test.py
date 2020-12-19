from py3kcap import pycap
import sys
packet = pycap(interface="wlan0",count=1)
for data in packet:
    for i in data:
        sys.stdout.write(hex(i))