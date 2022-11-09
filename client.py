import json

from socket import *
serverIP = "127.0.0.1"
serverPort = 10000
clientSocket = socket(AF_INET, SOCK_DGRAM)
while True:
    print("Input from the user:")
    user_input = input("Enter Domain Name: ")
    if user_input == "end":
        clientSocket.close()
        # TODO [QUESTION]: Any other actions needed to end the session?
        print("Session ended")
        break
    # TODO: Create a DNS query message (Hex)
    dns_query_header = ""
    dns_query_question = ""

    clientSocket.sendto(user_input.encode(), (serverIP, serverPort))
    server_res, serverAddress = clientSocket.recvfrom(2048)
    server_res = json.loads(server_res.decode())
    # print(server_res)
    output_str = ""
    for ip_addr in server_res["IP address"]:
        output_str += user_input + ": type " + server_res["Type"] + ", class " + server_res["Class"] +\
                     ", TTL " + server_res["TTL"] + ", addr (4) " + ip_addr
        # TODO [QUESTION]: Do we need to print "Input from the user:" and "Output:"?
        # TODO [QUESTION]: Isn't the IP address always 4-bytes?
        if (server_res["IP address"].index(ip_addr) + 1) != len(server_res["IP address"]):
            output_str += "\n"
    print(output_str)

    # TODO: Parse the server response into a DNS response message (Hex)
    dns_res_header = dns_query_header
    dns_res_question = dns_query_question
    dns_res_answer = ""
