import json

from socket import *
serverIP = "127.0.0.1"
serverPort = 10000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((serverIP, serverPort))
print("Server running...")

# A domain-name-to-IP-address map:
default_map = {
    "Type": "IN",
    "Class": "A",
    "TTL": 160,
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
    "TTL": 260,
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

while True:
    client_req, clientAddress = serverSocket.recvfrom(2048)
    print(client_req, clientAddress)
    domain_name = client_req.decode()
    serverSocket.sendto(json.dumps(domain_name_dict[domain_name]).encode(), clientAddress)

