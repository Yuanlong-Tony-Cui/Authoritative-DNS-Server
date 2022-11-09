from socket import *
serverIP = "127.0.0.1"
serverPort = 10000
clientSocket = socket(AF_INET, SOCK_DGRAM)
while True:
    print("Input from the user:")
    user_input = input("Enter Domain Name: ")
    if user_input == "end":
        clientSocket.close()
        # TODO: Any other actions needed to end the session?
        print("Session ended")

    # TODO: Create a DNS query message (Hex)
    dns_query_header = ""
    dns_query_question = ""

    clientSocket.sendto(user_input.encode(), (serverIP, serverPort))
    server_res, serverAddress = clientSocket.recvfrom(2048)
    server_res = server_res.decode()
    print(server_res)

    # TODO: Parse the server response into a DNS response message (Hex)
    dns_res_header = dns_query_header
    dns_res_question = dns_query_question
    dns_res_answer = ""
