import json
import random
from socket import *


def gen_dns_header(arg_msg_type):
    hex_str = ""

    # 1. Generate ID:
    binary_str = ""
    i = 0
    while i < 16:
        binary_str += str(random.randint(0, 1))
        i += 1
    # Binary -> integer -> "0x____"
    hex_str += format(int(binary_str, 2), "#06x")

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
    # Binary -> integer -> "0x____"
    hex_str += format(int(binary_str, 2), "#06x")

    # 3. Generate counts:
    hex_str += format(1, "#06x")  # QDCOUNT
    hex_str += format(0, "#06x")  # ANCOUNT TODO [QUESTION]: 0 resource record for "query" messages?
    hex_str += format(0, "#06x")  # NSCOUNT
    hex_str += format(0, "#06x")  # ARCOUNT

    # print(hex_str)
    return hex_str


def gen_dns_question(arg_domain_name):
    hex_str = ""

    # 1. QNAME:
    hex_str += format(len(arg_domain_name.split(".")[0]), "#04x")
    for letter in arg_domain_name:
        if letter == ".":
            hex_str += format((len(arg_domain_name.split(".")[1])), "#04x")
        else:
            # Convert char into integer then into "0x__":
            hex_str += format(ord(letter), "#04x")
    hex_str += format(0, "#04x")  # Terminated by "0x00"

    # 2. QTYPE & QCLASS:
    hex_str += format(1, "#06x")
    hex_str += format(1, "#06x")

    return hex_str


def format_hex_str(arg_hex_str):
    arg_hex_str = arg_hex_str.replace("0x", "")
    formatted_str = ""
    i = 0
    for hex_char in arg_hex_str:
        formatted_str += hex_char
        if i % 2 == 1 and i != len(arg_hex_str)-1:
            formatted_str += " "
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
        # TODO [QUESTION]: Any other actions needed to end the session?
        print("Session ended")
        break

    # Create a DNS query message (in Hex)
    dns_query = format_hex_str(gen_dns_header("query") + gen_dns_question(user_input))
    print(dns_query)

    # clientSocket.sendto(user_input.encode(), (serverIP, serverPort))
    # server_res, serverAddress = clientSocket.recvfrom(2048)
    # server_res = json.loads(server_res.decode())
    # # print(server_res)
    # output_str = ""
    # for ip_addr in server_res["IP address"]:
    #     output_str += user_input + ": type " + server_res["Type"] + ", class " + server_res["Class"] + \
    #                   ", TTL " + server_res["TTL"] + ", addr (4) " + ip_addr
    #     # TODO [QUESTION]: Do we need to print "Input from the user:" and "Output:"?
    #     # TODO [QUESTION]: Isn't the IP address always 4-bytes?
    #     if (server_res["IP address"].index(ip_addr) + 1) != len(server_res["IP address"]):
    #         output_str += "\n"
    # print(output_str)
    #
    # # TODO: Parse the server response into a DNS response message (Hex)
    # dns_res_header = dns_query_header
    # dns_res_question = dns_query_question
    # dns_res_answer = ""
