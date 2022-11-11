import json
import random
from socket import *


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


def format_hex_str(arg_hex_str):
    formatted_str = ""
    i = 0
    for hex_char in arg_hex_str:
        formatted_str += hex_char
        if i % 2 == 1 and i != len(arg_hex_str) - 1:
            formatted_str += " "
            if (i + 1) % (16 * 2) == 0:
                formatted_str += "\n"
        i += 1
    return formatted_str


def find_resource_records(arg_dns_res_str):
    rr_dict = {
        "type_arr": [],
        "class_arr": [],
        "ttl_arr": [],
        "ip_addr_arr": []
    }
    dns_res_arr = arg_dns_res_str.replace("\n", "").split(" ")
    i = 0
    for hex_item in dns_res_arr:
        if i >= len(dns_query.replace("\n", "").split(" ")):  # skips the header and question sections
            if hex_item == "c0" and dns_res_arr[i + 1] == "0c":
                # print(i, "Found one resource record.")
                type_hex = dns_res_arr[i + 2] + dns_res_arr[i + 3]
                if int(type_hex, 16) == 1:
                    rr_dict["type_arr"].append("A")
                class_hex = dns_res_arr[i + 4] + dns_res_arr[i + 5]
                if class_hex == "0001":
                    rr_dict["class_arr"].append("IN")
                ttl_hex = dns_res_arr[i + 6] + dns_res_arr[i + 7] + dns_res_arr[i + 8] + dns_res_arr[i + 9]
                rr_dict["ttl_arr"].append(str(int(ttl_hex, 16)))
                ip_addr_str = str(int(dns_res_arr[i + 12], 16)) + "." + \
                              str(int(dns_res_arr[i + 13], 16)) + "." + \
                              str(int(dns_res_arr[i + 14], 16)) + "." + \
                              str(int(dns_res_arr[i + 15], 16))
                rr_dict["ip_addr_arr"].append(ip_addr_str)
        i += 1
    # print(rr_dict)
    return rr_dict


serverIP = "127.0.0.1"
serverPort = 10000
clientSocket = socket(AF_INET, SOCK_DGRAM)
while True:
    print("Input from the user:")
    user_input = input("Enter Domain Name: ")
    if user_input == "end":
        clientSocket.close()
        print("Session ended")
        break

    # Create DNS query (in Hex):
    dns_query = format_hex_str(gen_dns_header("query", 0) + gen_dns_question(user_input))
    clientSocket.sendto(dns_query.encode(), (serverIP, serverPort))

    server_res, serverAddress = clientSocket.recvfrom(2048)
    resource_records = find_resource_records(server_res.decode())
    output_str = ""
    for ip_addr in resource_records["ip_addr_arr"]:
        # Assume IP addresses are unique:
        idx = resource_records["ip_addr_arr"].index(ip_addr)
        output_str += user_input + ": " + \
            "type " + resource_records["type_arr"][idx] + ", " + \
            "class " + resource_records["class_arr"][idx] + ", " + \
            "TTL " + resource_records["ttl_arr"][idx] + ", " + \
            "addr (" + str(len(ip_addr.split("."))) + ") " + ip_addr
        if (idx + 1) != len(resource_records["ip_addr_arr"]):
            output_str += "\n"
    print("Output:")
    print(output_str, "\n")
