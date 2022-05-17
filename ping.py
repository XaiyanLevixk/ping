import socket #https://stackoverflow.com/questions/36778544/read-ttl-from-an-icmp-message-received-via-python-raw-sockets
import os
import random #https://stackoverflow.com/questions/59959206/how-can-i-convert-this-string-into-a-human-readable-ip-address-in-php
import time
import select
import struct
# https://www.bitforestinfo.com/blog/01/21/code-to-ping-request-using-raw-python.html
ICMP_STRUCTURE_FMT = 'bbHHh'
IP_STRUCTURE_FMT = 'BBHHHBBHII'
ICMP_ECHO_REQUEST = 8

class ICMPPacket:
    def __init__(self,
        icmp_type = ICMP_ECHO_REQUEST,
        icmp_code = 0,
        icmp_chks = 0,
        icmp_id   = 1,
        icmp_seq  = 1,
        data      ='' ,
        ):

        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.icmp_chks = icmp_chks
        self.icmp_id   = icmp_id
        self.icmp_seq  = icmp_seq
        self.data      = data
        self.raw = None
        self.create_icmp_field()

    def create_icmp_field(self):
        self.raw = struct.pack(ICMP_STRUCTURE_FMT,
            self.icmp_type,
            self.icmp_code,
            self.icmp_chks,
            self.icmp_id,
            self.icmp_seq,
            )

        # calculate checksum
        self.icmp_chks = self.chksum(self.raw+self.data)

        self.raw = struct.pack(ICMP_STRUCTURE_FMT,
            self.icmp_type,
            self.icmp_code,
            self.icmp_chks,
            self.icmp_id,
            self.icmp_seq,
            )

        return 

    def chksum(self, msg):
        s = 0       # Binary Sum

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):

            a = ord(msg[i]) 
            b = ord(msg[i+1])
            s = s + (a+(b << 8))
            
        
        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff

        return s

def ext_ip_header(data):
    iph = struct.unpack(IP_STRUCTURE_FMT, data)
    data={
    "version" : iph[0],
    "type"    : iph[1],
    "length"  : iph[2],
    "id"      : iph[3],
    "flags"   : iph[4],
    "ttl"     : iph[5],
    "protocol": iph[6],
    "checksum": iph[7],
    "src_ip"  : iph[8],
    "dest_ip" : iph[9],
    }
    return data 


def ext_icmp_header(data):
    icmph=struct.unpack(ICMP_STRUCTURE_FMT, data)
    data={
    'type'  :   icmph[0],
    "code"  :   icmph[1],
    "checksum": icmph[2],
    'id'    :   icmph[3],
    'seq'   :   icmph[4],
    }
    return data




def catch_ping_reply(s, ID, time_sent, timeout=1):

    # create while loop
    while True:
        starting_time = time.time()     # Record Starting Time

        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)
        
        # check if timeout
        if process[0] == []:
            return

        # receive packet
        rec_packet, addr = s.recvfrom(1024)

        # extract icmp packet from received packet 
        icmp = rec_packet[20:28]
        iphe = rec_packet[:20]

        # extract information from icmp packet
        _id = ext_icmp_header(icmp)['id']

        # check identification
        if _id == ID:
            return ext_icmp_header(icmp), ext_ip_header(iphe), iphe["src_ip"], iphe["dest_ip"]
    return


#  
def single_ping_request(s, addr=None):

    # Random Packet Id
    pkt_id = random.randrange(10000,65000)
    
    # Create ICMP Packet
    packet = ICMPPacket(icmp_id=pkt_id).raw

    # Send ICMP Packet
    while packet:
        sent = s.sendto(packet, (addr, 1))
        packet = packet[sent:]

    return pkt_id


def main():
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # take Input
    addr = raw_input("[+] Enter Domain Name : ") 
    
    # Request sent
    t1 = time.time()
    ID = single_ping_request(s, addr)

    # Catch Reply
    reply1, reply2, iphe1, iphe2 = catch_ping_reply(s, ID, time.time())
    t2 = time.time()
    t3 = t2-t1
    if reply1:
        print reply1
        print reply2
        print t3

    # close socket
    s.close()
    return

if __name__=='__main__':
    main()