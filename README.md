# Instructions:

## Step 1
Open one terminal and run `python3 server.py`. Open another terminal and run `python3 client.py`.

## Step 2
To obtain particular resource records, as prompted by the client-side terminal, enter one of the following five domain names:

`google.com`, `youtube.com`, `uwaterloo.ca`, `wikipedia.org`, `amazon.ca`.

The client-side terminal will then print out all the available resource records of the specified domain name.

At the same time, the server-side terminal will print out the DNS requests and responses as hexadecimal strings.

## Step 3
To end the session, instead of entering a domain name, now enter `end` in the client-side terminal.

The client-side terminal will then print out "Session ended" to indicate the client has been closed.

However, the server will keep running in case there are any other clients that need the service.
