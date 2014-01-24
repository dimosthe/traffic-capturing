######### tcapture.py (traffic capture tool) ###########
## A tool for capturing incoming and outgoing traffic 
## from a network device
## run sudo python tcapture.py <network device name> <time in seconds> [-v],
## insert -v in order to get the src and dest of each packet
## requires pcapy and impacket python modules


from pcapy import findalldevs, open_live
from impacket import ImpactDecoder, ImpactPacket
import sys
import datetime
import socket
import fcntl
import struct


# gloabal variables
duration = 0
time1 = 0
time2 = 0
num_packets = 0
num_in_packets = 0
num_out_packets = 0
num_bytes = 0
num_in_bytes = 0
num_out_bytes = 0
interface = ''
interface_ip = ''
ver = None


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def sniff():
    global interface, interface_ip, time1
    # Open a live capture
    reader = open_live(interface, 1600, 0, 100)
    print "Listening on: %s, net=%s, ip=%s, mask=%s" %(interface, reader.getnet(), interface_ip, reader.getmask())

    # Set a filter to be notified only for TCP packets
    #reader.setfilter('ip proto \\tcp')
    
    time1 = datetime.datetime.now()

    # Run the packet capture loop
    reader.loop(0, callback)

def callback(hdr, data):

    global num_packets, num_bytes, time1, time2, duration
    global num_in_packets, num_out_packets, num_in_bytes, num_out_bytes
    global interface, interface_ip, ver
    
    
    # Parse the Ethernet packet
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(data)
    # Parse the IP packet inside the Ethernet packet
    iphdr = ether.child()

    # Parse the TCP/UDP packet inside the IP packet
    tcphdr = iphdr.child()

    # Only process SYN packets
    #if tcphdr.get_SYN() and not tcphdr.get_ACK():

    # Get the source and destination IP addresses
    try:
        src_ip = iphdr.get_ip_src()
        dst_ip = iphdr.get_ip_dst()
    except AttributeError:
        nun = 0
    else:
        # Print the results
        if(ver):
            print "Connection attempt %s -> %s" % (src_ip, dst_ip)
        num_packets += 1
        

        if(interface_ip == dst_ip):
            num_in_bytes += ether.get_size()
            num_in_packets += 1
        else:
            num_out_bytes += ether.get_size()
            num_out_packets += 1

        num_bytes += ether.get_size()
        time2 = datetime.datetime.now()
        dif = time2 - time1
        time_in_micro = dif.seconds*1000000 + dif.microseconds

        if(time_in_micro >= duration):
            print ('Total num of packets passed from %s: %d'% (interface, num_packets))
            print ('Num of incoming packets: %d'% num_in_packets)
            print ('Num of outgoing packets: %d'% num_out_packets)
            
            print ('Total num of bytes passed from %s: %d'% (interface, num_bytes))
            print ('Num of incoming bytes: %d'% num_in_bytes)
            print ('Num of outgoing bytes: %d'% num_out_bytes)
            
            bit_rate = (num_bytes*1000)/duration
            bit_rate_in = (num_in_bytes*1000)/duration
            bit_rate_out = (num_out_bytes*1000)/duration
            print('Total bit rate: %d KBps' % bit_rate)
            print('Incoming bit rate: %d KBps' % bit_rate_in)
            print('Outgoing bit rate: %d KBps' % bit_rate_out)
        
            sys.exit(1)

def main(argv):
    
    global duration, interface, interface_ip, ver
    
    if(len(argv) < 3):
        print('Invalid number of arguments')
        sys.exit(1)
    
    arg1 = argv[2]
    duration = int(arg1)*1000000 # if run python tcapture <network device name> <time in seconds>

    try:
        arg3 = argv[3]
    except IndexError:
        ver = None
    else:
        if(argv[3] == '-v'):
            ver = '-v'      # if run python tcapture <network device name> <time in seconds>

 
    
    #interface = get_interface()
    interface = argv[1]
    interface_ip = get_ip_address(interface)
    if interface:
        sniff()

if __name__ == "__main__":
    main(sys.argv)

