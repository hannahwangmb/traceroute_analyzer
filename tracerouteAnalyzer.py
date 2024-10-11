import sys
import struct
import statistics
from packet_struct import *

time = -1
routers = []
router = {
    'src_ip': '',
    'src_port': -1,
    'ttl': -1,
    'timestamp': [],
    'rtt': [],
    'seq_num': [],
}

datagrams = []
datagram = {
    'id': -1,
    'ttl': -1,
    'offset': -1,
    'mf': -1,
    'fragments': [],
    'src_port': -1,
    'dst_port': -1,
    'timestamp': -1,
    'seq_num': [],
}

fragment = {
    'offset': -1,
    'mf': -1,
    'timestamp': -1,
}

windows = False
ultimate_dest_found = False
ultimate_dest_ip = ''
dest_rtt = []
source_node_ip = ''
protocol_values = []

def read_global(f):
    # read global header
    global_header = f.read(24)
    my_global_header = Global_Header()
    my_global_header.get_global_header(global_header)
    endianness = my_global_header.endianness
    timestamp_resolution = my_global_header.timestamp_resolution
    return f, endianness, timestamp_resolution

# analyze each packet
def analyze_packet(f, endianness, timestamp_resolution):
    global connection
    global connections
    global ultimate_dest_found
    global ultimate_dest_ip
    global source_node_ip
    global datagrams
    global routers
    global datagram
    global router
    global fragment
    global dest_rtt
    global windows

    fragment = {
        'offset': -1,
        'mf': -1,
        'timestamp': -1,
    }
    # read packet header
    try:
        packet_header = f.read(16)
        if not packet_header:
            raise Exception("EOF")
    except:
        raise Exception("EOF")
    
    my_packet_header = Packet_Header()
    my_packet_header.get_packet_header(packet_header, endianness, timestamp_resolution)
    incl_len = my_packet_header.incl_len
    global time
    if time == -1:
        time = my_packet_header.timestamp
    
    # read ethernet header
    ethernet = f.read(14)
    # get last two bytes of ethernet header
    ethernet_type = ethernet[12:14]
    if ethernet_type != b'\x08\x00':
        f.read(incl_len - 14)
        return

    # read ip header
    ip_header = f.read(20)
    my_ip_header = IP_Header()
    my_ip_header.get_IP_header(ip_header)
    protocol = my_ip_header.protocol
    if protocol == 1 or protocol == 17:
        if protocol not in protocol_values:
            protocol_values.append(protocol)

    if protocol == 1:
        icmp_header = f.read(8)
        my_icmp_header = ICMP_Header()
        my_icmp_header.get_ICMP_type(icmp_header)

        
        if my_icmp_header.type == 11:
            if not windows:
                ip_header_2 = f.read(20)
                my_ip_header_2 = IP_Header()
                my_ip_header_2.get_IP_header(ip_header_2)
                udp_header = f.read(8)
                my_udp_header = UDP_Header()
                my_udp_header.get_UDP_port(udp_header)

                # store icmp connections
                src_ip = my_ip_header.src_ip
                router_found = False
                matching_datagram = next((datagram for datagram in datagrams if datagram['src_port'] == my_udp_header.src_port), None)
                for router in routers:
                    src_ip = router['src_ip']
                    if src_ip == my_ip_header.src_ip:
                        router['timestamp'].append(my_packet_header.timestamp)
                        if matching_datagram:
                            rttlist = [my_packet_header.timestamp - fragment['timestamp'] for fragment in matching_datagram['fragments']]
                            router['rtt'].extend(rttlist)
                        router_found = True
                        break
                if not router_found:
                    if matching_datagram:
                        rttlist = [my_packet_header.timestamp - fragment['timestamp'] for fragment in matching_datagram['fragments']]
                        new_router = {
                            'src_ip': my_ip_header.src_ip,
                            'src_port': my_udp_header.src_port,
                            'ttl': matching_datagram['ttl'],
                            'timestamp': [my_packet_header.timestamp],
                            'rtt': rttlist,
                        }
                        routers.append(new_router)
                    else:
                        print("error: router not found")
                f.read(incl_len -34-8-20-8)
                return
            else:
                # windows ICMP error
                ip_header_2 = f.read(20)
                my_ip_header_2 = IP_Header()
                my_ip_header_2.get_IP_header(ip_header_2)
                icmp_header_2 = f.read(8)
                # get sequence number
                icmp_seq_num = icmp_header_2[6:8]
                icmp_seq_num = struct.unpack('!H', icmp_seq_num)[0]
                src_ip = my_ip_header.src_ip
                matching_datagram = next((datagram for datagram in datagrams if datagram['seq_num'] == icmp_seq_num), None)
                # get matching router
                router_found = False
                for router in routers:
                    if router['src_ip'] == my_ip_header.src_ip:
                        router_found = True
                        router['timestamp'].append(my_packet_header.timestamp)
                        if matching_datagram:
                            rttlist = [my_packet_header.timestamp - fragment['timestamp'] for fragment in matching_datagram['fragments']]
                            router['rtt'].extend(rttlist)

                        break
                if not router_found:
                    if matching_datagram:
                        rttlist = [my_packet_header.timestamp - fragment['timestamp'] for fragment in matching_datagram['fragments']]
                        # store new router
                        new_router = {
                            'src_ip': my_ip_header.src_ip,
                            'src_port': -1,
                            'ttl': matching_datagram['ttl'],
                            'timestamp': [my_packet_header.timestamp],
                            'rtt': rttlist,
                            'seq_num': icmp_seq_num,
                        }
                        routers.append(new_router)
                    else:
                        print("error: router not found")
                f.read(incl_len - 34 - 8-20 - 8)
                return
  
        # linux captured file
        elif my_icmp_header.type == 3:
            ip_header_2 = f.read(20)
            my_ip_header_2 = IP_Header()
            my_ip_header_2.get_IP_header(ip_header_2)
            udp_header = f.read(8)
            my_udp_header = UDP_Header()
            my_udp_header.get_UDP_port(udp_header)
            # store rtt
            matching_datagram = next((datagram for datagram in datagrams if datagram['src_port'] == my_udp_header.src_port), None)
            if matching_datagram:
                rttlist = [my_packet_header.timestamp - fragment['timestamp'] for fragment in matching_datagram['fragments']]
                dest_rtt.extend(rttlist)
            if ultimate_dest_found == False:
                ultimate_dest_found = True
                ultimate_dest_ip = my_ip_header.src_ip            
                source_node_ip = my_ip_header.dst_ip
            f.read(incl_len -34-8-20-8)
            return

        # windows captured file
        elif my_icmp_header.type == 8:
            windows = True
            # get sequence number
            icmp_seq_num = icmp_header[6:8]
            icmp_seq_num = struct.unpack('!H', icmp_seq_num)[0]
            if my_ip_header.offset > 0:
                # find matching datagram
                datagram_found = False
                for datagram in datagrams:
                    if datagram['id'] == my_ip_header.id:
                        datagram_found = True
                        # store fragment
                        fragment = {
                            'offset': my_ip_header.offset,
                            'mf': my_ip_header.mf,
                            'timestamp': my_packet_header.timestamp,
                        }
                        datagram['fragments'].append(fragment)
                        if my_ip_header.mf == 0:
                            datagram['offset'] = my_ip_header.offset*8
                        f.read(incl_len - 42)
                        return
                if not datagram_found:
                    print("error: datagram not found")
                    f.read(incl_len - 42)
                    return
            # store fragment and datagram
            fragment = {
                'offset': my_ip_header.offset,
                'mf': my_ip_header.mf,
                'timestamp': my_packet_header.timestamp,
            }
            datagram = {
                'id': my_ip_header.id,
                'ttl': my_ip_header.ttl,
                'offset': my_ip_header.offset,
                'mf': my_ip_header.mf,
                'fragments': [fragment],
                'src_port': -1,
                'dst_port': -1,
                'timestamp': my_packet_header.timestamp,
                'seq_num': icmp_seq_num,
            }
            datagrams.append(datagram)
            f.read(incl_len - 42)
            return

        elif my_icmp_header.type == 0:
            # get sequence number
            icmp_seq_num = icmp_header[6:8]
            icmp_seq_num = struct.unpack('!H', icmp_seq_num)[0]
            matching_datagram = next((datagram for datagram in datagrams if datagram['seq_num'] == icmp_seq_num), None)
            if matching_datagram:
                rttlist = [my_packet_header.timestamp - fragment['timestamp'] for fragment in matching_datagram['fragments']]
                dest_rtt.extend(rttlist)
            if ultimate_dest_found == False:
                ultimate_dest_found = True
                ultimate_dest_ip = my_ip_header.src_ip
                source_node_ip = my_ip_header.dst_ip
            f.read(incl_len - 34-8)
            return


        else:
            f.read(incl_len - 42)
            return
            
    if protocol == 17:
        if my_ip_header.mf == 1:
            udp_header = f.read(8)
            my_udp_header = UDP_Header()
            my_udp_header.get_UDP_port(udp_header)
            # store new datagram
            datagram = {
                'id': my_ip_header.id,
                'ttl': my_ip_header.ttl,
                'offset': my_ip_header.offset,
                'mf': my_ip_header.mf,
                'fragments': [],
                'src_port': my_udp_header.src_port,
                'dst_port': my_udp_header.dst_port,
            }
            fragment = {
                'offset': my_ip_header.offset,
                'mf': my_ip_header.mf,
                'timestamp': my_packet_header.timestamp,
            }
            datagram['fragments'].append(fragment)
            datagrams.append(datagram)
            f.read(incl_len - 42)
            return
        elif my_ip_header.mf == 0:
            if my_ip_header.offset > 0:
                # find matching datagram
                datagram_found = False
                for datagram in datagrams:
                    if datagram['id'] == my_ip_header.id:
                        datagram_found = True
                        # store fragment
                        fragment = {
                            'offset': my_ip_header.offset,
                            'mf': my_ip_header.mf,
                            'timestamp': my_packet_header.timestamp,
                        }
                        datagram['fragments'].append(fragment)
                        datagram['offset'] = my_ip_header.offset*8
                        f.read(incl_len - 34)
                        return
                if not datagram_found:
                    print("error: datagram not found")
                    f.read(incl_len - 34)
                    return
            elif my_ip_header.offset == 0 :
                udp_header = f.read(8)
                my_udp_header = UDP_Header()
                my_udp_header.get_UDP_port(udp_header)
                if my_udp_header.dst_port >= 33434 and my_udp_header.dst_port <= 33529:
                    # store new fragment and datagram
                    fragment = {
                        'offset': my_ip_header.offset,
                        'mf': my_ip_header.mf,
                        'timestamp': my_packet_header.timestamp,
                    }
                    datagram = {
                        'id': my_ip_header.id,
                        'ttl': my_ip_header.ttl,
                        'offset': my_ip_header.offset,
                        'mf': my_ip_header.mf,
                        'fragments': [fragment],
                        'src_port': my_udp_header.src_port,
                        'dst_port': my_udp_header.dst_port,
                        'timestamp': my_packet_header.timestamp,
                    }

                    datagrams.append(datagram)
                    f.read(incl_len - 42)
                    return
                else:
                    f.read(incl_len - 42)
                    return
        else:
            f.read(incl_len - 34)
            return

    else:
        f.read(incl_len - 34)
        return

def main():
    # read file name
    if len(sys.argv) != 2:
        print("Usage: python3 TracerouteAnalyzer.py [filename]")
        sys.exit(1)
    else:
        filename = sys.argv[1]
        f = open(filename, 'rb')
        f, endianness, timestamp_resolution = read_global(f)
        while True:
            try:
                analyze_packet(f, endianness, timestamp_resolution)
            except Exception as e:
                break
        
        print("The IP address of the source node:", source_node_ip)
        print("The IP address of ultimate destination node:", ultimate_dest_ip)
        print("The IP addresses of the intermediate destination nodes:")
        #sort routers by ttl 
        routers.sort(key=lambda x: x['ttl'])
        # print router number, ip, and ttl
        for i, router in enumerate(routers):
            print("      router {}: {}".format(i + 1, router['src_ip']))
        print("")
        print("The values in the protocol field of IP headers:")
        # print protocol values
        for protocol in protocol_values:
            if protocol == 1:
                print("      {}: ICMP".format(protocol))
            elif protocol == 17:
                print("      {}: UDP".format(protocol))
        print("")
        for datagram in datagrams:
            if len(datagram['fragments']) > 1:
                print("The number of fragments created from the original datagram {} is: {}".format(datagram['id'], len(datagram['fragments'])))
            else:
                print("The number of fragments created from the original datagram {} is: {}".format(datagram['id'], 0))
            print("The offset of the last fragment is:", datagram['offset'])
            print('')
        # print average and s.d. rtt for each router
        for router in routers:
            if len(router['rtt']) > 1:
                print("The avg RTT between {} and {} is: {} ms, the s.d. is: {} ms".format(source_node_ip, router['src_ip'], round(statistics.mean(router['rtt'])*1000, 2), round(statistics.stdev(router['rtt'])*1000, 2)))
            else:
                print("The avg RTT between {} and {} is: {} ms, the s.d. is: {} ms".format(source_node_ip, router['src_ip'], round(router['rtt'][0]*1000,2), 0))
        # print average and s.d. rtt for destination
        if len(dest_rtt) > 1:
            print("The avg RTT between {} and {} is: {} ms, the s.d. is: {} ms".format(source_node_ip, ultimate_dest_ip, round(statistics.mean(dest_rtt)*1000, 2), round(statistics.stdev(dest_rtt)*1000, 2)))
        else:
            print("The avg RTT between {} and {} is: {} ms, the s.d. is: {} ms".format(source_node_ip, ultimate_dest_ip, round(dest_rtt[0]*1000, 2), 0))


        f.close()


if __name__ == "__main__":
    main()    