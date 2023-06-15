import functions as f
import pcap as p
import packet as pkt
import ethernet as e
import ip as i
import transport as t
import dns as d
import type as TYPE

data = f.read_file('syn_attack.pcap')

##### skip global header
g_payload = p.skip(data)
n_payload = g_payload

index = 0
while True:
    # input()
    index += 1
    if len(n_payload) < 16:
        break
    print()

    ##### parse packet header
    print("########## {} Packet Header ##########".format(index))
    p_header, p_payload = pkt.parse(n_payload)
    n_payload = p_payload[p_header.orig_len:]
    p_payload = p_payload[:p_header.orig_len]
    print(p_header)
    # print(p_payload)

    ##### parse ethernet header
    print("########## Ethernet ##########")
    e_header, e_payload = e.parse(p_payload)
    print(e_header)

    ##### check ipv4
    if not e_header.e_type == TYPE.IPV4:
        continue
    
    ##### parse ip header
    print("########## IP Header ##########")
    i_header, i_payload = i.parse(e_payload)
    print(i_header)

    ##### check UDP
    if i_header.protocol == TYPE.UDP:
        ##### parse udp header
        print("########## UDP Header ##########")
        u_header, u_payload = t.udp_parse(i_payload)
        print(u_header)

        ##### only DNS Response
        if not u_header.src_port == 53:
            continue

        ##### parse DNS header
        print("########## DNS Header ##########")
        d_header, d_payload = d.parse(u_payload)
        print(d_header)
        # f.print_answer_ip(d_header.answers)

    elif i_header.protocol == TYPE.TCP:
        ##### parse tcp header
        print("########## TCP Header ##########")
        t_header, t_payload = t.tcp_parse(i_payload)
        print(t_header)
