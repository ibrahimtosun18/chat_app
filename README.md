# Secure Chat Application with OpenSSL

This is a simple chat application that allows users to communicate securely over a network using OpenSSL for encryption and authentication.

## Features

- Secure communication using SSL/TLS encryption.
- Multiple clients can connect to the server simultaneously.
- Each client is identified by a unique name.
- Messages sent by clients are broadcasted to all other connected clients.
- Server and client codes are provided in C language.

## Requirements

- Linux environment (tested on Ubuntu).
- OpenSSL library installed.
- Basic knowledge of command-line interface (CLI).

## How to Use

### Server

1. Compile the server code:
    ```bash
    gcc chat_server.c -o chat_server -lpthread -lssl -lcrypto
    ```

2. Run the server:
    ```bash
    ./chat_server
    ```

3. The server will start listening for incoming connections on port 8080.

### Client

1. Compile the client code:
    ```bash
    gcc chat_client.c -o chat_client -lssl -lcrypto -lpthread
    ```

2. Run the client:
    ```bash
    ./chat_client
    ```

3. Enter your name when prompted.

4. Start typing messages to chat with other connected clients. Enter 'exit' to quit.

### Spy Scenario
1. Start spyClient2 on another terminal to see if anyone who don't have SSL key can connect the line. This scenario show secure communication is established between clients.



## File Structure

- `chat_server.c`: Source code for the server application.
- `chat_client.c`: Source code for the client application.
- `server-cert.pem`: Server certificate file (replace with your own certificate).
- `server-key.pem`: Server private key file (replace with your own private key).
- `ca-cert.pem`: Certificate authority (CA) certificate file (used for client verification).

## Notes

- Make sure to replace the certificate and private key files with your own files generated for your server.
- Ensure that the CA certificate file is trusted by the client for successful SSL/TLS handshake.
- The client application allows multiple clients to connect to the server simultaneously.


## License

This project is licensed under the [MIT License](LICENSE).
