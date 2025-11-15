#!/usr/bin/env python3
import socket
import struct
import sys
import random

# DNS record types
TYPE_A = 1
TYPE_NS = 2
CLASS_IN = 1
PORT = 53
BUFFER_SIZE = 2048  # increased buffer to handle large responses
TIMEOUT = 5.0

def build_query(domain_name):
    transaction_id = random.randint(0, 65535)
    flags = 0x0100  # standard query
    qdcount = 1
    ancount = nscount = arcount = 0
    header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)
    
    # Question section
    qname = b''.join(bytes([len(part)]) + part.encode() for part in domain_name.split('.')) + b'\x00'
    qtype = TYPE_A
    qclass = CLASS_IN
    question = qname + struct.pack(">HH", qtype, qclass)
    
    return header + question, transaction_id

def parse_name(message, offset):
    labels = []
    jumped = False
    original_offset = offset
    max_len = len(message)
    while offset < max_len:
        length = message[offset]
        if length == 0:
            offset += 1
            break
        # pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= max_len:
                offset += 2
                break
            pointer = ((length & 0x3F) << 8) | message[offset+1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
        else:
            offset += 1
            if offset + length > max_len:
                labels.append(message[offset:].decode('latin1', errors='ignore'))
                offset = max_len
            else:
                labels.append(message[offset:offset+length].decode('latin1', errors='ignore'))
                offset += length
    return '.'.join(labels), (offset if not jumped else original_offset)

def parse_rr(message, offset):
    name, offset = parse_name(message, offset)
    if offset + 10 > len(message):
        return {"name": name, "type": None, "value": None}, len(message)
    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", message[offset:offset+10])
    offset += 10
    rdata = message[offset:offset+rdlength] if offset+rdlength <= len(message) else b''
    offset += rdlength
    
    if rtype == TYPE_A:
        ip = '.'.join(str(b) for b in rdata)
        return {"name": name, "type": rtype, "value": ip}, offset
    elif rtype == TYPE_NS:
        ns_name, _ = parse_name(message, offset - rdlength)
        return {"name": name, "type": rtype, "value": ns_name}, offset
    else:
        return {"name": name, "type": rtype, "value": rdata}, offset

def parse_response(message):
    header = struct.unpack(">HHHHHH", message[:12])
    qdcount = header[2]
    ancount = header[3]
    nscount = header[4]
    arcount = header[5]
    offset = 12

    # Skip questions
    for _ in range(qdcount):
        _, offset = parse_name(message, offset)
        offset += 4  # qtype + qclass

    answers = []
    authority = []
    additional = []

    for _ in range(ancount):
        rr, offset = parse_rr(message, offset)
        answers.append(rr)
    for _ in range(nscount):
        rr, offset = parse_rr(message, offset)
        authority.append(rr)
    for _ in range(arcount):
        rr, offset = parse_rr(message, offset)
        additional.append(rr)
    return answers, authority, additional

def print_overview(server_ip, answers, authority, additional):
    print("----------------------------------------------------------------")
    print(f"DNS server to query: {server_ip}")
    print("Reply received. Content overview:")
    print(f"{len(answers)} Answers.")
    print(f"{len(authority)} Intermediate Name Servers.")
    print(f"{len(additional)} Additional Information Records.")
    if answers:
        print("Answers section:")
        for rr in answers:
            if rr['type'] == TYPE_A:
                print(f"Name : {rr['name']} IP: {rr['value']}")
    if authority:
        print("Authority Section:")
        for rr in authority:
            if rr['type'] == TYPE_NS:
                print(f"Name : {rr['name']} Name Server: {rr['value']}")
    if additional:
        print("Additional Information Section:")
        for rr in additional:
            if rr['type'] == TYPE_A:
                print(f"Name : {rr['name']} IP : {rr['value']}")
    print("----------------------------------------------------------------")

def choose_next_server(authority, additional):
    for rr in authority:
        if rr['type'] == TYPE_NS:
            for add in additional:
                if add['type'] == TYPE_A and add['name'] == rr['value']:
                    return add['value']
    return None

def query_dns(server_ip, domain_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    query, transaction_id = build_query(domain_name)
    try:
        sock.sendto(query, (server_ip, PORT))
        response, _ = sock.recvfrom(BUFFER_SIZE)
        answers, authority, additional = parse_response(response)
        return answers, authority, additional
    except Exception as e:
        print(f"[!] Error querying {server_ip}: {e}")
        return None, None, None
    finally:
        sock.close()

def iterative_resolve(domain_name, root_ip):
    server_ip = root_ip
    while True:
        answers, authority, additional = query_dns(server_ip, domain_name)
        if answers is None:
            print(f"[!] Could not query server {server_ip}")
            return
        print_overview(server_ip, answers, authority, additional)
        if answers and any(rr['type']==TYPE_A for rr in answers):
            return
        next_ip = choose_next_server(authority, additional)
        if next_ip is None:
            print("[!] Could not find next server IP in Additional section")
            return
        server_ip = next_ip

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} domain-name root-dns-ip")
        sys.exit(1)
    domain_name = sys.argv[1]
    root_ip = sys.argv[2]
    iterative_resolve(domain_name, root_ip)
