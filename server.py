import random
# from client import gen_dns_header, gen_dns_question

from socket import *
serverIP = "127.0.0.1"
serverPort = 10000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((serverIP, serverPort))
print("Server running...")

# A domain-name-to-IP-address map:
default_map = {
    "Type": "A",
    "Class": "IN",
    "TTL": "160",
    "IP address": []
}
domain_name_dict = {
    "google.com": default_map.copy(),
    "youtube.com": default_map.copy(),
    "uwaterloo.ca": default_map.copy(),
    "wikipedia.org": default_map.copy(),
    "amazon.ca": default_map.copy()
}
domain_name_dict["google.com"].update({
    "TTL": "260",
    "IP address": ["192.165.1.1", "192.165.1.10"]
})
domain_name_dict["youtube.com"].update({
    "IP address": ["192.165.1.2"]
})
domain_name_dict["uwaterloo.ca"].update({
    "IP address": ["192.165.1.3"]
})
domain_name_dict["wikipedia.org"].update({
    "IP address": ["192.165.1.4"]
})
domain_name_dict["amazon.ca"].update({
    "IP address": ["192.165.1.5"]
})
# print("domain_name_dict:", domain_name_dict)


def find_domain_name(arg_query_str):
    query_hex_arr = arg_query_str.split(" ")
    name = ""
    for hex_item in query_hex_arr:
        i = query_hex_arr.index(hex_item)
        if i > 12:
            if hex_item == "00":
                break
            if int(hex_item, 16) < 10:  # integer: 0 ~ 9
                if i != 12:
                    name += "."
            else:   # chars
                name += chr(int(hex_item, 16))
    return name


def gen_dns_header(arg_msg_type, arg_num_rr):
    hex_str = ""

    # 1. Generate ID:
    binary_str = ""
    i = 0
    while i < 16:
        binary_str += str(random.randint(0, 1))
        i += 1
    # Binary -> integer -> "0x____"
    hex_str += format(int(binary_str, 2), "04x")

    # 2. Generate flags:
    binary_str = ""
    # 1-bit QR:
    if arg_msg_type == "query":
        binary_str += "0"
    elif arg_msg_type == "response":
        binary_str += "1"
    binary_str += "0000"  # 4-bit OPCODE
    binary_str += "1000"  # AA, TC, RD, and RA
    binary_str += "0000000"  # 3-bit ZZ and 4-bit RCODE
    # Binary -> integer -> "____"
    hex_str += format(int(binary_str, 2), "04x")

    # 3. Generate counts:
    hex_str += format(1, "04x")  # QDCOUNT
    hex_str += format(arg_num_rr, "04x")  # ANCOUNT
    hex_str += format(0, "04x")  # NSCOUNT
    hex_str += format(0, "04x")  # ARCOUNT

    # print(hex_str)
    return hex_str


def gen_dns_question(arg_domain_name):
    hex_str = ""

    # 1. QNAME:
    hex_str += format(len(arg_domain_name.split(".")[0]), "02x")
    for letter in arg_domain_name:
        if letter == ".":
            hex_str += format((len(arg_domain_name.split(".")[1])), "02x")
        else:
            # Convert char into integer then into "__":
            hex_str += format(ord(letter), "02x")
    hex_str += format(0, "02x")  # Terminated by "00"

    # 2. QTYPE & QCLASS:
    hex_str += format(1, "04x")
    hex_str += format(1, "04x")

    return hex_str


def gen_dns_answer(arg_ttl, arg_ip_addr_arr):
    hex_str = ""
    for ip_addr in arg_ip_addr_arr:
        hex_str += "c00c"   # NAME
        hex_str += "0001"   # TYPE
        hex_str += "0001"   # CLASS
        hex_str += format(int(arg_ttl), "08x")    # TTL
        # Count and parse the octets in each IP address:
        hex_str += format(len(ip_addr.split(".")), "04x")
        for num in ip_addr.split("."):
            hex_str += format(int(num), "02x")
    return hex_str


def format_hex_str(arg_hex_str):
    formatted_str = ""
    i = 0
    for hex_char in arg_hex_str:
        formatted_str += hex_char
        if i % 2 == 1 and i != len(arg_hex_str)-1:
            formatted_str += " "
            if (i+1) % (16*2) == 0:
                formatted_str += "\n"
        i += 1
    return formatted_str


while True:
    client_req, clientAddress = serverSocket.recvfrom(2048)
    # print(client_req, clientAddress)
    query_hex_str = client_req.decode()
    domain_name = find_domain_name(query_hex_str)
    # print(domain_name)
    print("Request:")
    print(query_hex_str)

    dns_res_header = gen_dns_header(
        "response",
        len(domain_name_dict[domain_name]["IP address"])
    )
    dns_res_question = gen_dns_question(domain_name)
    dns_res_answer = gen_dns_answer(
        domain_name_dict[domain_name]["TTL"],
        domain_name_dict[domain_name]["IP address"]
    )
    dns_response = format_hex_str(dns_res_header + dns_res_question + dns_res_answer)
    print("Response:")
    print(dns_response)
    serverSocket.sendto(dns_response.encode(), clientAddress)

