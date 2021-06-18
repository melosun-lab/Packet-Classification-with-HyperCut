#!/usr/bin/env python

import sys
from scapy.all import *
import time

start_time = -1
count = 0
def convert_to_int(addr):
    parts = addr.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + (int(parts[3]))

def handle_pkt(pkt):
#    pkt.show2()
    global start_time,count
    if start_time == -1:
	start_time = time.time()
    orig = [convert_to_int(pkt[IP].src),convert_to_int(pkt[IP].dst)]
    if pkt.haslayer(TCP):
	orig.append(int(pkt[TCP].sport))
	orig.append(int(pkt[TCP].dport))
	orig.append(6)
    if pkt.haslayer(UDP):
	orig.append(int(pkt[UDP].sport))
	orig.append(int(pkt[UDP].dport))
	orig.append(17)
    rule_found = False
    rule_num = -1
    if orig[0] >= 0 and orig[0] <= 1 and orig[1] >= 14 and orig[1] <= 15 and orig[2] == 3 and orig[3] >= 1 and orig[3] <=4 and orig[4] == 17:
	rule_found = True
	if int(pkt[IP].tos == 0):
	    rule_num = 0 
    elif orig[0] >= 0 and orig[0] <= 1 and orig[1] >= 14 and orig[1] <= 15 and orig[2] == 2 and orig[3] == 3 and orig[4] == 17:
	rule_found = True
	if int(pkt[IP].tos == 1):
	    rule_num = 1
    elif orig[0] >= 0 and orig[0] <= 1 and orig[1] >= 8 and orig[1] <= 11 and orig[2] >= 1 and orig[2] <= 4 and orig[3] == 3 and orig[4] == 6:
	 rule_found = True
	 if int(pkt[IP].tos == 2):
	    rule_num = 2
    elif orig[0] >= 0 and orig[0] <= 1 and orig[1] >= 8 and orig[1] <= 11 and orig[2] >= 1 and orig[2] <= 4 and orig[3] == 2 and orig[4] == 6:
	rule_found = True
	if int(pkt[IP].tos == 3):
	    rule_num = 3
    elif orig[0] >= 0 and orig[0] <= 1 and orig[1] >= 8 and orig[1] <= 11 and orig[2] == 3 and orig[3] == 4 and orig[4] == 6:
	rule_found = True
	if int(pkt[IP].tos == 4):
	    rule_num = 4 
    elif orig[0] >= 0 and orig[0] <= 7 and orig[1] >= 14 and orig[1] <= 15 and orig[2] == 3 and orig[3] == 2 and orig[4] == 17:
	rule_found = True
	if int(pkt[IP].tos == 5):
	    rule_num = 5
    elif orig[0] >= 0 and orig[0] <= 7 and orig[1] >= 14 and orig[1] <= 15 and orig[2] == 3 and orig[3] == 3 and orig[4] == 17:
	rule_found = True
	if int(pkt[IP].tos == 6):
	    rule_num = 6
    elif orig[0] >= 0 and orig[0] <= 7 and orig[1] >= 8 and orig[1] <= 15 and orig[2] >= 1 and orig[2] <= 4 and orig[3] >= 1 and orig[3] <= 4 and orig[4] == 6:
	rule_found = True
	if int(pkt[IP].tos == 7):
	    rule_num = 7
    elif orig[0] >= 0 and orig[0] <= 15 and orig[1] >= 4 and orig[1] <= 7 and orig[2] >= 1 and orig[2] <= 4 and orig[3] >= 1 and orig[3] <= 4 and orig[4] == 6:
	rule_found = True
	if int(pkt[IP].tos == 8):
	    rule_num = 8
    elif orig[0] >= 0 and orig[0] <= 15 and orig[1] >= 0 and orig[1] <= 7 and orig[2] >= 1 and orig[2] <= 4 and orig[3] == 2 and orig[4] == 17:
	rule_found = True
	if int(pkt[IP].tos == 9):
	    rule_num = 9
    elif orig[0] >= 0 and orig[0] <= 15 and orig[1] >= 0 and orig[1] <= 15 and orig[2] >= 1 and orig[2] <= 4 and orig[3] >= 1 and orig[3] <= 4 and orig[4] == 6:
	rule_found = True
	if int(pkt[IP].tos == 11):
	    rule_num = 11
    else:
	print orig, "RULE NOT FOUND!"
    if (rule_found and rule_num >= 0):
	print orig, "Rule: ", rule_num, pkt[Raw].load
	count+=1
    elif(rule_found and rule_num == -1):
	print "ERROR MATCHING RULE", orig

#    print orig
    print (time.time()-start_time)*1000,count,(time.time()-start_time)*1000//count
    sys.stdout.flush()


def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
