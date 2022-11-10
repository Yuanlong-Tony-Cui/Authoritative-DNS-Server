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
        if i % 2 == 1 and i != len(arg_hex_str)-1:
            formatted_str += " "
            if (i+1) % (16*2) == 0:
                formatted_str += "\n"
        i += 1
    return formatted_str


serverIP = "127.0.0.1"
serverPort = 10000
clientSocket = socket(AF_INET, SOCK_DGRAM)
while True:
    # print("Input from the user:")
    user_input = input("Enter Domain Name: ")
    if user_input == "end":
        clientSocket.close()
        print("Session ended")
        break

    # Create DNS query (in Hex):
    dns_query = format_hex_str(gen_dns_header("query", 0) + gen_dns_question(user_input))
    print(dns_query)
    clientSocket.sendto(dns_query.encode(), (serverIP, serverPort))

    # TODO: Parse the DNS response (hex string) into formatted client-side output:
    server_res, serverAddress = clientSocket.recvfrom(2048)

    # server_res, serverAddress = clientSocket.recvfrom(2048)
    # # print(server_res)
    # output_str = ""
    # for ip_addr in server_res["IP address"]:
    #     output_str += user_input + ": type " + server_res["Type"] + ", class " + server_res["Class"] + \
    #                   ", TTL " + server_res["TTL"] + ", addr (4) " + ip_addr
    #     # TODO [QUESTION]: Do we need to print "Input from the user:" and "Output:"?
    #     if (server_res["IP address"].index(ip_addr) + 1) != len(server_res["IP address"]):
    #         output_str += "\n"
    # print(output_str)