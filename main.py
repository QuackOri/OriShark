import functions as f
import pcap as p
import packet as pkt
import ethernet as e
import ip as i
import transport as t
import dns as d

data = f.read_file('syn_attack.pcap')

##### skip global header
g_payload = p.skip(data)
n_payload = g_payload
while True:
    # input()
    if len(n_payload) < 16:
        break

    ##### parse packet header
    p_header, p_payload = pkt.parse(n_payload)
    n_payload = p_payload[p_header.orig_len:]
    p_payload = p_payload[:p_header.orig_len]
    # print(p_header)
    # print(p_payload)

    ##### parse ethernet header
    e_header, e_payload = e.parse(p_payload)
    # print(e_header)
    ##### check ipv4
    if not f.is_ipv4(e_header):
        continue
    
    ##### parse ip header
    i_header, i_payload = i.parse(e_payload)
    # print(i_header)

    ##### check UDP
    if not f.which_protocol(i_header) == "UDP":
        continue
    
    ##### parse udp header
    u_header, u_payload = t.udp_parse(i_payload)
    # print(u_header)
    ##### only DNS Response
    if not u_header.src_port == 53:
        continue

    ##### parse DNS header
    d_header, d_payload = d.parse(u_payload)
    f.print_answer_ip(d_header.answers)
