# E2EE-chat
End to end encrypted chat demo
This is an application written in Python to serve as a working demo of a basic end to end encryption chat. It uses Diffie-Hellman key exchange and AES-CGM for secure messaging. 

## Usage
Start server with
```
python3 app.py -s [-p <port>]
```
Default port is 5000
And start client with
```
python3 app.py -c <host:port>
```
```
Available commands:
    /register <username> <password> - Create a new account
    /login <username> <password>    - Log in to existing account
    /chat <username>                - Request to chat with a user
    /accept                         - Accept a chat request
    /exit                           - Exit chat session
    /help                           - Show this help message
```
