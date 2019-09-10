# server_client
A client-server model basic approach with server supporting more than one client simultaneously.

# about the client-server model
The client-server model describes how a server provides resources and services to one or more clients. Examples of servers include web servers, mail servers, and file servers. Each of these servers provide resources to client devices, such as desktop computers, laptops, tablets, and smartphones. Most servers have a one-to-many relationship with clients, meaning a single server can provide resources to multiple clients at one time.

When a client requests a connection to a server, the server can either accept or reject the connection. If the connection is accepted, the server establishes and maintains a connection with the client over a specific protocol. 

The client-server model may be contrasted to the P2P model, in which clients connect directly to each other. In a P2P connection, there is no central server required, since each machine acts as both a client and a server.

# usage

**server:** python server.py *{-d}* *{-c <software_config_file>}* *{-u <allowed_devices_file>}*

**client:** ./client *{-d}* *{-c <software_config_file>}* *{-f <network_dev_config_file>}*

Where arguments inside '{}' are optional arguments.

**use one terminal for each process, one for the server and as many terminals as desired for the clients**
