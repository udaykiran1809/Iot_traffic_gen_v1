import pandas as pd
from scapy.all import *
import random
import secrets
import sys
import ast

pcap_file = 'cic_1_4.pcap'
writer = PcapWriter(pcap_file, append=True, sync=True)

mac_table = {
    '44:07:0b:65:c9:43':'192.168.1.123',
    '88:50:f6:0a:8c:7e':'192.168.1.132',
    '9c:8e:cd:0c:66:6d':'192.168.1.145',
    'a8:80:55:ee:0e:ec':'192.168.1.120',
    'cc:f4:11:a6:21:bf':'192.168.1.131',
    'e4:fa:c4:b2:bc:3c':'192.168.1.126',
    'e4:fa:c4:b2:cc:3f':'192.168.1.129',
    'e4:fa:c4:b2:cc:a7':'192.168.1.133',
    'e4:fa:c4:b2:f6:ee':'192.168.1.104',
    'f8:0f:f9:3e:fa:02':'192.168.1.112',
    'fc:49:2d:35:f9:44':'192.168.1.121'
}

ip_table = {
    '192.168.1.123' :'44:07:0b:65:c9:43',
    '192.168.1.132' : '88:50:f6:0a:8c:7e',
    '192.168.1.145' : '9c:8e:cd:0c:66:6d',
    '192.168.1.120' : 'a8:80:55:ee:0e:ec',
    '192.168.1.131' : 'cc:f4:11:a6:21:bf',
    '192.168.1.126' : 'e4:fa:c4:b2:bc:3c',
    '192.168.1.128' : '88:50:F6:0A:A5:48',
    '192.168.1.129' : 'e4:fa:c4:b2:cc:3f',
    '192.168.1.133' : 'e4:fa:c4:b2:cc:a7',
    '192.168.1.104' : 'e4:fa:c4:b2:f6:ee',
    '192.168.1.112' : 'f8:0f:f9:3e:fa:02',
    '192.168.1.121' : 'fc:49:2d:35:f9:44',
    '192.168.1.142' : '30:13:8b:ba:6f:16',
    '192.168.1.1': '14:91:82:bf:bd:a3'
}

dns_table = {
    'time.nist.gov':59335,
    'n-use1-devs.tplinkcloud.com':15011,
    'n-deventry.tplinkcloud.com':15011,
    'api.gelighting.com':35363,
    'cm.gelighting.com':8981,
    'de.ntp.org.cn':49689,
    'dh.amcrestsecurity.com':18855,
    'config.amcrestcloud.com':27613,
    'p2p.amcrestview.com':12325,
    'www.google.com':43424,
    '_googlezone._tcp.local':45365,
    '_googlecast._tcp.local':32943,
}

def icmp(ip_src,ip_dst,Len, mac,sp,dp,interf):
    # Minimal radiotap header
    radiotap_header = RadioTap()

    # Dot11 header for the ICMP request (client to AP)
    dot11_header = Dot11(
        type=2,                # Data frame (not management)
        subtype=0,             # Regular data frame
        addr1="14:91:82:BF:BD:A4",   # Destination MAC (AP's BSSID)
        addr2=mac,   # Source MAC (client's spoofed MAC)
        addr3="14:91:82:BF:BD:A4"    # AP's BSSID (used for routing)
    )

    # Logical Link Control (LLC) layer
    llc_layer = LLC(dsap=0xAA, ssap=0xAA, ctrl=3)

    # SNAP layer (required for encapsulating IP traffic)
    snap_layer = SNAP(OUI=0x000000, code=0x0800)  # 0x0800 is EtherType for IP

    # IP layer for ICMP Echo Request
    ip_layer = IP(src=ip_src, dst=ip_dst)

    # ICMP Echo Request layer (ping)
    icmp_request = ICMP(type=8, seq=1) / b"Ping request"

    # Build the complete ICMP Echo Request packet
    icmp_request_packet = (
        radiotap_header /
        dot11_header /
        llc_layer /
        snap_layer /
        ip_layer /
        icmp_request
    )
    current_length = len(icmp_request_packet)

    if current_length < Len:
        padding_length = Len - current_length
        packet = icmp_request_packet / Padding(load=b'\x00' * padding_length)
        # sendp(packet, iface=interf,count =1)
        writer.write(packet)
    else:
        writer.write(icmp_request_packet)
        # sendp(icmp_request_packet, iface="wlan0mon",count =1)
    return len(icmp_request_packet)

def arp(ip_src, ip_dst, Len,mac,sp,dp,interf):
    # Create a RadioTap header with detailed fields
    radiotap_header = RadioTap(
        # present="Flags+Rate+Channel+MCS",
        # Flags="FCS",                   # Set Frame Check Sequence flag (avoids malformed packet)
        # Rate=19.5,                     # Data rate in Mbps
        # Channel=2417,                  # Frequency for channel 2 on 2.4 GHz band
        # ChannelFlags="2GHz",           # Indicates 2.4 GHz band
        # dBm_AntSignal=-37,             # Signal strength in dBm
        # MCS={"index": 2, "bw": 20}     # MCS index for 802.11n HT with 20 MHz bandwidth
    )

    # Create a Dot11 header for a QoS data frame
    dot11_header = Dot11(
        type=2,  # Type 2 indicates a data frame
        subtype=8,  # Subtype 8 for a QoS Data frame
        addr1="ff:ff:ff:ff:ff:ff",  # Broadcast MAC address for ARP request
        addr2=mac,  # Source MAC address
        addr3="14:91:82:BF:BD:A4"   # AP's BSSID
    )

    # Add QoS header for QoS data frames
    dot11_qos_header = Dot11QoS()

    # Create LLC and SNAP headers for encapsulating the ARP packet over 802.11
    llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    snap_header = SNAP(OUI=0x000000, code=0x0806)  # 0x0806 is the EtherType for ARP

    # Create the ARP request packet
    arp_request = ARP(
        hwsrc=mac,  # Source MAC address
        # psrc="192.168.1.123",       # Source IP address
        hwdst="ff:ff:ff:ff:ff:ff",  # Target MAC address (broadcast)
        pdst=ip_dst,       # Target IP address
        op=1                        # ARP request
    )

    
    # Combine all headers and layers to form the complete packet
    packet = radiotap_header / dot11_header / dot11_qos_header / llc_header / snap_header / arp_request

    # Calculate the current length of the packet and pad it to 123 bytes if needed
    current_length = len(packet)
    if current_length < Len:
        padding_length = 123 - current_length
        packet = packet / Padding(load=b'\x00' * padding_length)

    # Save the packet to a pcap file
    # wrpcap("arp_packet_123_bytes_with_radio_info.pcap", packet)

    # print("Packet saved to arp_packet_123_bytes_with_radio_info.pcap with length:", len(packet))
    # sendp(packet, iface=interf,count =1)
    writer.write(packet)

    arp_reply = ARP(
        op=2,              # ARP reply
        hwsrc=mac,     # Your MAC address (source)
        psrc=ip_src,       # The IP address you want to claim (source IP)
        hwdst=ip_table["192.168.1.112"],     # Target MAC address (destination)
        pdst=ip_dst        # Target IP address
    )

    # Combine all headers and layers to form the complete packet
    packet = radiotap_header / dot11_header / dot11_qos_header / snap_header / arp_reply

    # Send the packet with Scapy
    # sendp(packet, iface=interf, count=1, verbose=True)
    writer.write(packet)

    return len(packet)


def udp(ip_src, ip_dst, Len, mac, sp, dp, interf,raw_load):
    
    
    radiotap_header = RadioTap(
        present="Flags+Rate+Channel",  # Specifies the fields included in the header
        Flags="FCS",                   # Set Frame Check Sequence flag (avoids malformed packet)
        Rate=2,                        # Data rate (in Mbps), 1 Mbps works universally on 2.4 GHz
        Channel=2412,                  # Channel 1 on 2.4 GHz (2412 MHz)
        ChannelFlags="2GHz"            # Indicate this packet is for 2.4 GHz band
    )
    
    dot11_header = Dot11(
        addr1="14:91:82:BF:BD:A4",  # AP's BSSID (destination MAC)
        addr2=mac,  # Spoofed device's MAC (source MAC)
        addr3="14:91:82:BF:BD:A4"   # AP's BSSID (used for routing)
    )

    if Len > 600:
        size = 20 + len(raw_load) + 4
    else:
        pay_load_len = abs(Len-86)
        raw_load = secrets.token_bytes(5+pay_load_len)
        # raw_load = b'Uday Kiran'
        size = 20 + len(raw_load) + 4
    
    ip_layer = IP(src=ip_src, dst=ip_dst,len=size)  # Spoofed IP addresses
    if dp==53:
        dp = 9930
    udp_layer = UDP(sport=sp, dport=dp, len=len(raw_load) + 4)

    packets = (
        radiotap_header /
        dot11_header /
        LLC() / SNAP() /
        ip_layer /
        udp_layer /
        raw_load
    )

    # packets = packets.__class__(bytes(packet))

    # sendp(packets, iface=interf,count =1)
    writer.write(packets)
    return len(packets)

def tcp_packet(ip_src, ip_dst, Len, mac, mac_1, sp, dp, interf, seq_, win):
    radiotap_header = RadioTap(
    present="Flags+Rate+Channel",  # Specifies the fields included in the header
    Flags="FCS",                   # Set Frame Check Sequence flag (avoids malformed packet)
    Rate=2,                        # Data rate (in Mbps), 1 Mbps works universally on 2.4 GHz
    Channel=2412,                  # Channel 1 on 2.4 GHz (2412 MHz)
    ChannelFlags="2GHz"            # Indicate this packet is for 2.4 GHz band
    )
    # print(ip_src,ip_dst)
    dot11_header = Dot11(
        addr1="14:91:82:BF:BD:A4",  # AP's BSSID (destination MAC)
        addr2=mac,  # Spoofed device's MAC (source MAC)
        addr3="14:91:82:BF:BD:A4"   # AP's BSSID (used for routing)
    )
    
    dot11_header_in = Dot11(
        addr1="14:91:82:BF:BD:A4",  # AP's BSSID (destination MAC)
        addr2= mac_1,  # Spoofed device's MAC (source MAC)
        addr3="14:91:82:BF:BD:A4"   # AP's BSSID (used for routing)
    )

    # pay_load = b"let's ge"
    # print(len(pay_load))
    # print(size)
    current_timestamp = 5000035
    
    if Len > 112:
        pay_load_len = abs(Len-113)
        pay_load = secrets.token_bytes(15+pay_load_len)
        size = 20 + 20 + len(pay_load)
        ip_layer = IP(src=ip_src, dst=ip_dst, len=size)  # Spoofed IP addresses
        tcp_layer = TCP(sport=sp, dport=dp, seq=seq_,window = win,options=[
            ('NOP', None), 
            ('NOP', None)
        ])
    else:
        pay_load_len = abs(Len-86)
        pay_load = secrets.token_bytes(5+pay_load_len)
        size = 20 + 20 + len(pay_load) - 4
        ip_layer = IP(src=ip_src, dst=ip_dst, len=size)  # Spoofed IP addresses
        tcp_layer = TCP(sport=sp, dport=dp, seq=seq_, window=win)

    packets = (
        radiotap_header /
        dot11_header /
        LLC() / SNAP() /
        ip_layer /
        tcp_layer /
        pay_load
    )

    # sendp(packets, iface=interf,count =1)
    writer.write(packets)
    # print(len(packet))
    
    seq_num_out = tcp_layer.seq  # Get the sequence number from the outgoing packet
    ack_num_in = seq_num_out + 1

    # Incoming packet

    ip_layer_in = IP(src=ip_dst, dst=ip_src, len=size)

    # TCP layer with switched source and destination ports and SYN-ACK flag for response
    if Len > 100:
        tcp_layer_in = TCP(sport=dp, dport=sp, seq=seq_+1, ack=ack_num_in, window=win,options=[
            ('NOP', None), 
            ('NOP', None), 
            ('Timestamp', (current_timestamp+456, 0))
        ])
    else:
        tcp_layer_in = TCP(sport=dp, dport=sp, seq=seq_+1, ack=ack_num_in, window=win)

    incoming_packet = (
        radiotap_header/
        dot11_header_in/
        LLC() / SNAP() /
        ip_layer_in /
        tcp_layer_in /
        pay_load
    )

    # sendp(incoming_packet, iface=interf,count =1)
    writer.write(incoming_packet)

    return len(incoming_packet)+len(packets)
    

def stun(ip_src, ip_dst, Len, mac, sp, dp, interf):
    radiotap_header = RadioTap(
        present="Flags+Rate+Channel",  # Specifies the fields included in the header
        Flags="FCS",                   # Set Frame Check Sequence flag (avoids malformed packet)
        Rate=2,                        # Data rate (in Mbps), 1 Mbps works universally on 2.4 GHz
        Channel=2412,                  # Channel 1 on 2.4 GHz (2412 MHz)
        ChannelFlags="2GHz"            # Indicate this packet is for 2.4 GHz band
    )
    
    dot11_header = Dot11(
        addr1="14:91:82:BF:BD:A4",  # AP's BSSID (destination MAC)
        addr2=mac,  # Spoofed device's MAC (source MAC)
        addr3="14:91:82:BF:BD:A4"   # AP's BSSID (used for routing)
    )
    
    # pay_load = b'\xd0\xf2\x81\xf8\x8b\xff\x9a\xf7\xd5\xef\x94\xb6\xd1\xb4\xc0\x9f\xec\x95\xe6\x8f\xe1\x87\xe8\xca\xf0\x8b\xa9\xda\xad\xf2\x84\xe1\x93\xb1\x8b\xa9\x98\xb6\x86\xa8\x99\xaa\x8a\xc8\xbd\xd4\xb8\xdc\xfc\xce\xfa\xca\xfb\xca\xfd\xdd\x8f\xea\x86\xa8\x99\xaf\x9d\xae\x9b\xae\x8c\xa0\x82\xea\x9d\xc2\xb4\xd1\xa3\x81\xbb\x99\xac\x82\xb2\x90\xbc\x9e\xf3\x9c\xf8\x9d\xf1\xd3\xe9\xcb\x83\xd0\xe1\xd1\xe2\xca\x9f\xcc\xe5\xc7\xeb\xc9\xad\xc8\xbe\xd7\xb4\xd1\x98\xfc\xde\xe4\xc6\xfe\xce\xfe\xc8\x8c\xcf\xfb\xb8\xfa\xc8\xf0\xb1\x84\xc0\xf5\xc3\x82\xb6\x84\xb2\xf6\xb0\xf2\xc1\xf7\xc0\xf7\xc1\x80\xb6\x8e\xb9\x8b\xb9\x8a\xbb\x83\xc1\xf8\xbe\x9c\xb0\x92\xfd\x98\xf5\xbc\xd8\xfa\xc0\xe2\xd0\xe1\xd0\x93\xaa\x9b\xdd\xee\xad\x9b\xdd\x9c\xa5\x96\xa3\x95\xad\xe9\xd1\xe0\xd8\xed\xdf\xeb\xad\xe8\xd9\xee\xde\x9d\xd8\x9b\xb9\x95\xb7\xdf\xa8\xe1\x85\xa7\x9d\xbf\xfd\xcf\xfa\xb9\xfb\xb8\x8d\xbe\x8b\xba\xfe\xba\x82\xbb\x89\xcc\x8d\xbb\x82\xc3\x81\xb5\x87\xb6\x8f\xb6\xf0\xc5\xfc\xb9\x8d\xbc\x9e\xb2\x90\xe2\x91\xe2\x8b\xa9\x93\xbe\x8d\xb8\x94\xb6\xda\xbb\xcf\xa6\xd2\xa7\xc3\xa6\xf9\x90\xb2\x88\xbb\x89\xbf\x8f\xb7\x84\xa8\x8a\xe6\x89\xe7\x80\xe9\x9d\xe8\x8c\xe9\xb6\xdf\xfd\xc7\xea\xd2\xe7\xd3\xeb\xdc\xe4\xc8\xea\x8b\xe7\x8e\xef\x9c\xbe\x84\xa6\xed\x8c\xff\x9e\xbe\xed\x80\xe1\x93\xe7\xc7\x97\xfb\x8e\xe9\xc9\xfa\xd8\xf4\xd6\xa5\xd1\xb0\xc4\xb1\xc2\xe0\xda\xf8\x96\xf3\x84\xa6\x8a\xa8\xc7\xa5\xc1\x9e\xed\x9f\xfc\xde\xe4\xc6\xb2\xc2\xae\xc7\xa9\xc2\xe0\xcc\xee\x83\xea\x89\xd6\xa2\xdb\xab\xce\xec\xd6\xf4\xbd\xf2\xa6\x88\xdb\x96\xd7\x85\xd1\x81\xcd\x98\xdf\x8c\xdb\x92\xc6\x85\xcd\xef\xc3\xe1\x87\xe2\x83\xf7\x82\xf0\x95\xb7\x8d\xaf\xfb\xb2\xff\xdd\xf1\xd3\xbe\xdf\xbc\x9e\xa4\x86\xc3\xf7\xcd\x8b\xca\xf0\xb3\x87\xbd\xff\xcd\xf7\xb4\xf7\xcd\xfe\xb8\x9a\xb6\x94\xe1\x91\xf5\x94\xe0\x89\xe7\x80\xa2\x98\xa8\x84\xa6\xca\xaf\xcb\x94\xfb\x9d\xfb\xd9\xe3\xd3\xff\xdd\xaf\xca\xa6\xc7\xbe\xe1\x92\xe6\x87\xf3\x96\xb4\x8e\xbe\x92\xb0\xdf\xb1\xee\x9a\xf3\x9e\xfb\xd9\xe3\xd3\xff\xdd\xb4\xd7\xb8\xd6\x89\xe1\x80\xf3\x9b\xb9\x83\xa1\x83\xaf\x8d\xe9\x8c\xfa\xa5\xcb\xaa\xc7\xa2\x80\xba\x98\xcb\xa6\xc7\xb5\xc1\xe1\xb6\xdf\xf2\xb4\xdd\xfd\xad\xc1\xb4\xd3\xf3\xbe\xd7\xb9\xd0\xf2\xde\xfc\x9d\xfe\x8a\xe3\x95\xf0\xaf\xc2\xad\xc9\xac\x8e\xb4\x96\xf8\x97\xf9\x9c\xbe\x92\xb0\xde\xbb\xc3\xb7\xe8\x89\xea\x9e\xf7\x98\xf6\xd4\xee\x95\xb7\xc3\xba\xca\xaf\x8d\xb7\x9a\xab\xd6\xfa\xd8\xbd\xcf\xbd\xe2\x81\xee\x8a\xef\xcd\xf7\xc7\xba\xc7\xba'
    
    stun = Raw(load=b'\x00\x01\x00\x00\x00\x00\x00\x01\xda\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    size = 20 + len(stun) + 4
    stun_1 = Raw(load=b'\x00\x02\x00\x00\x00\x00\x00\x01\xda\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    ip_layer = IP(src=ip_src, dst=ip_dst,len=size)  # Spoofed IP addresses
    udp_layer = UDP(sport=sp, dport=dp, len=len(stun) + 4)
    
    packets_ = (
        radiotap_header /
        dot11_header /
        LLC() / SNAP() /
        ip_layer /
        udp_layer /
        stun
    )
    
    # sendp(packets_, iface=interf,count =1)
    writer.write(packets_)
    
    ip_layer = IP(dst=ip_src, src=ip_dst,len=size)  # Spoofed IP addresses
    udp_layer = UDP(dport=sp, sport=dp, len=len(stun_1) + 4)
    
    packets = (
        radiotap_header /
        dot11_header /
        LLC() / SNAP() /
        ip_layer /
        udp_layer /
        stun_1
    )
    
    # sendp(packets, iface=interf,count =1)
    writer.write(packets)

    return len(packets_)+len(packets)

def url_to_ip(url):
    try:
        return socket.gethostbyname(url)
    except socket.gaierror:
        print("Invalid URL")
        return "145.276.3.4"

def dns(ip_src, mac, sp, dp,url, interf):
    # Radiotap header (you can customize the fields if needed)
    radiotap_header = RadioTap()

    # Dot11 header (this is for data frames)
    dot11_header = Dot11(
        type=2,                # Data frame (not management)
        subtype=0,             # Regular data frame
        addr1="14:91:82:BF:BD:A4",   # Destination MAC (AP's BSSID)
        addr2=mac,   # Source MAC (client's spoofed MAC)
        addr3="14:91:82:BF:BD:A4"    # AP's BSSID (used for routing)
    )

    if url == "www.google.com":
        ip_dst = "8.8.8.8"
    else:
        ip_dst = "192.168.1.1"

    # Logical Link Control (LLC) layer
    llc_layer = LLC(dsap=0xAA, ssap=0xAA, ctrl=3)

    # SNAP layer (required for encapsulating IP traffic)
    snap_layer = SNAP(OUI=0x000000, code=0x0800)  # 0x0800 is EtherType for IP

    # IP layer for DNS query (spoofed)
    ip_layer = IP(src=ip_src,dst=ip_dst)

    # UDP layer for DNS
    udp_layer = UDP(sport=sp, dport=dp)

    # DNS query layer
    dns_query = DNS(rd=1, qd=DNSQR(qname=url))

    # Build the DNS query packet
    dns_query_packet = (
        radiotap_header /
        dot11_header /
        llc_layer /
        snap_layer /
        ip_layer /
        udp_layer /
        dns_query
    )

    # Send the DNS query packet
    # sendp(dns_query_packet, iface=interf, count=1)
    writer.write(dns_query_packet)



    # Use the same Transaction ID for response (0x0000)
    dns_response = DNS(
        id=dns_query.id,       # Match the DNS query Transaction ID
        qr=1,                  # This is a response
        aa=1,                  # Authoritative answer
        qd=DNSQR(qname=url),  # Original query
        an=DNSRR(rrname=url, ttl=300, rdata= url_to_ip(url))  # Response with IP address 1.2.3.4
    )

    # Build the DNS response packet
    dns_response_packet = (
        radiotap_header /
        dot11_header /
        llc_layer /
        snap_layer /
        ip_layer /
        udp_layer /
        dns_response
    )

    #Send the DNS response packet
    # sendp(dns_response_packet, iface=interf, count=1)
    writer.write(dns_response_packet)

    return len(dns_query_packet)+len(dns_response_packet)

if __name__ == "__main__":
    
    pcap_file = "pcaps/LabCapture23JulyMidnight-dec.pcap"
    ip_address = "192.168.1.129"
    packets = rdpcap(pcap_file)
    filtered_packets = [pkt for pkt in packets if IP in pkt and (pkt[IP].src == ip_address or pkt[IP].dst == ip_address)]
    packet_udp = filtered_packets[4]
    raw_load = bytes(packet_udp[Raw].load)

    interf = 'wlan0mon'
    df = pd.DataFrame(pd.read_csv("cic_test_1.csv"))
    dev = df['Device'], Ip_src = df['Source']
    Ip_dst = df['Destination'], pro = df['Protocol']
    leng = df['Length'], ttl = df['TTL'], src_p = df['Src Port']
    dst_p = df['Dst Port'], tcp_win = df['Tcp Window']
    dns_q = df['dns.qry_name'], tp =df['Total Packets']
    total_pac_sum = df['Total Packets'].sum()
    total_size = 0
    temp_size = 0
    l_ = 0
    seq = 0
    win = 2456
    for i in range(len(dev)):
        ip_src = Ip_src[i]
        ip_src = ast.literal_eval(ip_src)
        ip_src = random.choice(ip_src)
        print(type(ip_src))
        ip_dst = Ip_dst[i]
        ip_dst = ast.literal_eval(ip_dst)
        ip_dst = random.choice(ip_dst)
        temp = (tp[i]/total_pac_sum) * 100
        print(temp)
        
        if temp > 0 and temp <= 5:
            threshold = total_pac_sum * 0.1
        elif temp > 5 and temp <= 10:
            threshold = total_pac_sum * 0.3
        elif temp > 10:
            threshold = total_pac_sum * 0.5
        k = 0
        if ip_src == str(0):
            continue
        else:
            try:
                p = eval(pro[i].replace("‘", "'").replace("’", "'"))
                l = eval(leng[i].replace("‘", "'").replace("’", "'"))
                tt = eval(ttl[i].replace("‘", "'").replace("’", "'"))
                sp = eval(src_p[i].replace("‘", "'").replace("’", "'"))    
                dp = eval(dst_p[i].replace("‘", "'").replace("’", "'"))
                tcp_w = eval(tcp_win[i].replace("‘", "'").replace("’", "'"))
                dns_ = eval(dns_q[i].replace("‘", "'").replace("’", "'"))

                for j in range(0,threshold):
                    choice = random.choice(p)
                    index = p.index(choice)
                    print(choice)

                    if l_ == 0:
                        choice = 'DNS'
                    
                    if choice == 'UDP' or choice == 'TPLINK-SMARTHOME/JSON' or choice == 'TFTP' or choice == 'SSDP' or choice == 'Portmap':
                        if int(sp[index]) == 123 or int(sp[index]) == 68:
                            continue
                        temp_size = udp(ip_src,ip_dst,l[index],dev[i],int(sp[index]),int(dp[index]),interf, raw_load)
                        l_ = l_+1
                        print('udp_packet_sent',l_)
                        total_size = total_size+temp_size
                        k = 0
                        print('Total size:', total_size)
                    elif choice == 'TCP' or choice == 'BitTorrent' or choice == 'HTTP' or choice == 'IMAP':
                        print("PAss")
                        print(ip_src,ip_dst)
                        temp_size=tcp_packet(ip_src,ip_dst,l[index],dev[i],dev[i+1],int(sp[index]),int(dp[index]),interf, seq,win)
                        seq = seq+1
                        if seq == 5000:
                            seq=1
                        win = win+10
                        if not (0 <= win <= 65535):
                            win = 0
                        total_size = total_size+temp_size
                        print('Total size:', total_size)
                        l_ = l_+1
                        k = 0
                        print('tcp_packet_sent',l_)
                    elif choice == 'CLASSIC-STUN':
                        temp_size=stun(ip_src,ip_dst,l[index],dev[i],int(sp[index]),int(dp[index]),interf)
                        total_size = total_size+temp_size
                        l_ = l_+1
                        print('stun_packet_sent',l_)
                        print('Total size:', total_size)
                        k = 0
                    elif choice == 'DNS' and k == 0:
                        url = random.choice(dns_)
                        choice = 'DNS'
                        if choice in p:
                            index = p.index(choice)
                            temp_size=dns(ip_src,dev[i],int(sp[index]),int(dp[index]),url,interf)
                            total_size = total_size+temp_size
                            l_ = l_+1
                            print('dns_packet_sent',l_)
                            print('Total size:', total_size)
                            k = 1
                        else:
                            continue
                        
                    elif choice == 'ARP':
                        continue
                    elif choice == 'ICMP':
                        temp_size=icmp(ip_src,ip_dst,l[index],dev[i],int(sp[index]),int(dp[index]),interf)
                        total_size = total_size+temp_size
                        l_ = l_+1
                        print('ICMP_packet_sent',l_)
                        print('Total size:', total_size)
            except Exception as e:
                print("exception:",e)

    print('Total size:', total_size)