import struct
import ipaddress
        
# pcap 파일을 오픈
fd = open("syn_attack.pcap", "rb")
# pcap 파일내용을 data 변수에 담는다.
data = fd.read()
fd.close()
offset = 0
offset += 24
packet_count = 0
while True:
    packet_count +=1
    ts_sec = struct.unpack("<l", data[offset:offset + 4])[0]
    offset += 4
    ts_usec = struct.unpack("<l", data[offset:offset + 4])[0]
    offset += 4
    incl_len = struct.unpack("<l", data[offset:offset + 4])[0]
    offset += 4
    orig_len = struct.unpack("<l", data[offset:offset + 4])[0]
    offset += 4
    packet_data = data[offset : offset + orig_len]
    ### packet data analysis
    packet_offset = 0    
    # 2계층 Ethernet Frame
    dmac = packet_data[packet_offset : packet_offset + 6]
    packet_offset += 6
    smac = packet_data[packet_offset : packet_offset + 6]
    packet_offset += 6
    ethernet_type = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
    packet_offset += 2
    if ethernet_type == 8:
        ### ipv4
        packet_data = packet_data[packet_offset : ]
        packet_offset = 0
        version = struct.unpack("<B", packet_data[packet_offset : packet_offset + 1])[0]
        packet_offset += 1
        service_field = struct.unpack("<B", packet_data[packet_offset : packet_offset + 1])[0]
        packet_offset += 1
        total_length = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
        packet_offset += 2
        identification = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
        packet_offset += 2
        flag = struct.unpack("<B", packet_data[packet_offset : packet_offset + 1])[0]
        fragment_offset = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
        packet_offset += 2
        ttl = struct.unpack("<B", packet_data[packet_offset : packet_offset + 1])[0]
        packet_offset += 1
        protocol = struct.unpack("<B", packet_data[packet_offset : packet_offset + 1])[0]
        packet_offset += 1
        checksum = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
        packet_offset += 2
        src_ip = packet_data[packet_offset : packet_offset + 4]
        packet_offset += 4
        dst_ip = packet_data[packet_offset : packet_offset + 4]
        packet_offset += 4
        if protocol == 6:
            ### TCP 
            packet_data = packet_data[packet_offset:]
            packet_offset = 0
            src_port = struct.unpack(">H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            dst_port = struct.unpack(">H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            seq_number = packet_data[packet_offset : packet_offset + 4]
            packet_offset += 4
            ack_number = packet_data[packet_offset : packet_offset + 4]
            packet_offset += 4
            header = protocol = struct.unpack("<B", packet_data[packet_offset : packet_offset + 1])[0]
            header = int(header / 4)
            packet_offset += 1
            flags = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            flags_bit = format(flags, 'b')[-6:]
            flags = ""
            if flags_bit[0] == "1":
                flags += "u"
            if flags_bit[1] == "1":
                flags += "a"
            if flags_bit[2] == "1":
                flags += "p"
            if flags_bit[3] == "1":
                flags += "r"
            if flags_bit[4] == "1":
                flags += "s"
            if flags_bit[5] == "1":
                flags += "f"
            tcp_checksum = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            #print(packet_count, ipaddress.IPv4Address(src_ip), ipaddress.IPv4Address(dst_ip), ttl, src_port, dst_port, flags)
        
            try:
                urgent_pointer = struct.unpack("<H", packet_data[packet_offset : packet_offset + 2])[0]
                urgent_pointer += 2
            except:
                pass
            tcp_payload = packet_data[header:]
            if "\r\n\r\n".encode("utf-8") in tcp_payload:
                for http_header in tcp_payload.decode("utf-8").split("\r\n"):
                    if len(http_header) == 0:
                        continue
        elif protocol == 17:
            packet_data = packet_data[packet_offset:]
            packet_offset = 0
            src_port = struct.unpack(">H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            dst_port = struct.unpack(">H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            udp_length = struct.unpack(">H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            udp_checksum = struct.unpack(">H", packet_data[packet_offset : packet_offset + 2])[0]
            packet_offset += 2
            udp_payload = packet_data[packet_offset:]
            print(len(udp_payload))
            if dst_port == 53:
                dns_query = udp_payload[12:]
                dns_offset = 0
                query = b""
                while True:
                    dot = dns_query[dns_offset]
                    if dot == 0:
                        break
                    dns_offset += 1
                    query += dns_query[dns_offset : dns_offset + dot]
                    dns_offset += dot
                    
                    query += b"."
                    if dns_offset > len(dns_query):                        
                        break
                print(query[:-1])                
                dns_offset += 1
            elif src_port == 53:
                dns_response = udp_payload[18:]
                dns_offset = 0
                answer_count = struct.unpack(">H", udp_payload[6:8])[0]
                print(answer_count)
                
                
                
                query = b""
                while True:
                    dot = dns_query[dns_offset]
                    if dot == 0:
                        break
                    dns_offset += 1
                    query += dns_query[dns_offset : dns_offset + dot]
                    dns_offset += dot
                    
                    query += b"."
                    if dns_offset > len(dns_query):                        
                        break
                print(query[:-1])                
                dns_offset += 1
                pass
            print(ipaddress.IPv4Address(src_ip), ipaddress.IPv4Address(dst_ip), ttl, src_port, dst_port, udp_payload)
    offset += orig_len
    
    if offset >= len(data):
        print(packet_count)
        break

'''
magic = data[offset : offset + 4]
offset += 4
major_version = data[offset : offset + 2]
offset += 2
minor_version = data[offset : offset + 2]
offset += 2
'''

