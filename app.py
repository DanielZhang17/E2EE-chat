import socket
import sys
import threading
import base64
import argparse
import json
import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import serialization


class SecureChatServer:
    def __init__(self, host="0.0.0.0", port=5000):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}
        self.registered_users = self.load_registered_users()
        self.online_users = {}
        self.pending_requests = {}
        self.chat_pairs = {}  # Store active chat pairs
        print("Initializing server...")

        # Generate DH parameters that will be shared with clients
        self.parameters = dh.generate_parameters(
            generator=2, key_size=2048, backend=default_backend()
        )
        # Serialize parameters for sharing
        self.parameters_bytes = self.parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        )
        print(f"Server started on {host}:{port}")

    def load_registered_users(self):
        if os.path.exists("users_db.json"):
            with open("users_db.json", "r") as file:
                return json.load(file)
        return {}

    def save_registered_users(self):
        with open("users_db.json", "w") as file:
            json.dump(self.registered_users, file)

    def forward_message(self, from_username, message):
        try:
            # Find the chat partner
            if from_username in self.chat_pairs:
                to_username = self.chat_pairs[from_username]
                if to_username in self.online_users:
                    to_socket = self.online_users[to_username]
                    # Forward the encrypted message as is
                    to_socket.send(message.encode("utf-8"))
                    return True
            return False
        except Exception as e:
            print(f"Error forwarding message: {e}")
            return False

    def handle_client(self, client_socket):
        # First, send DH parameters to client
        client_socket.send(self.parameters_bytes)

        current_username = None
        try:
            while True:
                data = client_socket.recv(4096).decode("utf-8")
                if not data:
                    break

                # Try to parse as JSON first
                try:
                    data_json = json.loads(data)
                    command = data_json.get("command")
                    if command == "/exit":
                        if not current_username:
                            current_username = data_json.get("current_username")
                        if current_username in self.chat_pairs:
                            partner = self.chat_pairs[current_username]
                            if partner in self.online_users:
                                self.online_users[partner].send(
                                    "CHAT_ENDED: Your chat partner has left.".encode(
                                        "utf-8"
                                    )
                                )
                            del self.chat_pairs[current_username]
                            del self.chat_pairs[partner]
                        break
                    if command == "/chat":
                        if current_username is None:
                            client_socket.send(
                                "ERROR: You must be logged in to initiate a chat.".encode(
                                    "utf-8"
                                )
                            )
                            continue
                        
                        target_user = data_json.get("target_user")
                        public_key_b64 = data_json.get("public_key")

                        if target_user in self.online_users:
                            if target_user == current_username:
                                client_socket.send(
                                    "ERROR: Cannot chat with yourself.".encode("utf-8")
                                )
                                continue

                            target_socket = self.online_users[target_user]
                            request_data = {
                                "type": "chat_request",
                                "from": current_username,
                                "public_key": public_key_b64,
                            }
                            target_socket.send(json.dumps(request_data).encode("utf-8"))
                            self.pending_requests[target_user] = current_username
                            client_socket.send(
                                f"REQUEST_SENT: Chat request sent to {target_user}.".encode(
                                    "utf-8"
                                )
                            )
                            print(
                                f"Forwarded chat request from '{current_username}' to '{target_user}'"
                            )
                        else:
                            client_socket.send(
                                "ERROR: User not online or not found.".encode("utf-8")
                            )

                    elif command == "/accept":
                        if current_username is None:
                            client_socket.send(
                                "ERROR: You must be logged in to accept chat requests.".encode(
                                    "utf-8"
                                )
                            )
                            continue

                        public_key_b64 = data_json.get("public_key")
                        if current_username in self.pending_requests:
                            requester_username = self.pending_requests[current_username]
                            # Set up chat pairs
                            self.chat_pairs[current_username] = requester_username
                            self.chat_pairs[requester_username] = current_username

                            requester_socket = self.online_users[requester_username]
                            accept_data = {
                                "type": "chat_accepted",
                                "from": current_username,
                                "public_key": public_key_b64,
                            }
                            requester_socket.send(
                                json.dumps(accept_data).encode("utf-8")
                            )
                            del self.pending_requests[current_username]
                        else:
                            client_socket.send(
                                "ERROR: No pending chat requests.".encode("utf-8")
                            )

                    continue
                # if JSON failed to parse
                except json.JSONDecodeError:
                    # Check if this is an encrypted message
                    if current_username and current_username in self.chat_pairs:
                        # Forward encrypted message to chat partner
                        success = self.forward_message(current_username, data)
                        if not success:
                            client_socket.send(
                                "ERROR: Could not send message. Chat may have ended.".encode(
                                    "utf-8"
                                )
                            )
                        continue

                    # Handle regular commands
                    command_parts = data.split()
                    command = command_parts[0]
                    params = command_parts[1:] if len(command_parts) > 1 else []
                    if  command == "/exit":
                        if current_username in self.chat_pairs:
                            partner = self.chat_pairs[current_username]
                            if partner in self.online_users:
                                self.online_users[partner].send(
                                    "CHAT_ENDED: Your chat partner has left.".encode(
                                        "utf-8"
                                    )
                                )
                            del self.chat_pairs[current_username]
                            del self.chat_pairs[partner]

                    if command == "/register":
                        username, hashed_password = params
                        if username in self.registered_users:
                            client_socket.send(
                                "ERROR: Username already taken.".encode("utf-8")
                            )
                        else:
                            self.registered_users[username] = hashed_password
                            self.save_registered_users()
                            client_socket.send(
                                "REGISTERED: Registration successful.".encode("utf-8")
                            )

                    elif command == "/login":
                        username, hashed_password = params
                        if (
                            username in self.registered_users
                            and self.registered_users[username] == hashed_password
                        ):
                            if username in self.online_users:
                                client_socket.send(
                                    "ERROR: User already logged in.".encode("utf-8")
                                )
                                continue
                            self.online_users[username] = client_socket
                            current_username = username
                            client_socket.send(
                                f"LOGGED_IN: Welcome {username}.".encode("utf-8")
                            )
                            print(
                                f"User '{username}' logged in. Online users: {list(self.online_users.keys())}"
                            )
                        else:
                            client_socket.send(
                                "ERROR: Invalid credentials.".encode("utf-8")
                            )

                    elif command == "/exit":
                        if current_username in self.chat_pairs:
                            partner = self.chat_pairs[current_username]
                            if partner in self.online_users:
                                self.online_users[partner].send(
                                    "CHAT_ENDED: Your chat partner has left.".encode(
                                        "utf-8"
                                    )
                                )
                            del self.chat_pairs[current_username]
                            del self.chat_pairs[partner]
                        

        except Exception as e:
            print(f"Client error: {e}")
        finally:
            if current_username and current_username in self.online_users:
                del self.online_users[current_username]
                if current_username in self.chat_pairs:
                    partner = self.chat_pairs[current_username]
                    if partner in self.online_users:
                        self.online_users[partner].send(
                            "CHAT_ENDED: Your chat partner has disconnected.".encode(
                                "utf-8"
                            )
                        )
                    del self.chat_pairs[current_username]
                    if partner in self.chat_pairs:
                        del self.chat_pairs[partner]
            client_socket.close()
            print(f"Client disconnected: {current_username}")


    def start(self):
        while True:
            client_socket, addr = self.server.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()


class SecureChatClient:
    def __init__(self, host="127.0.0.1", port=5000):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.in_chat = False
        self.session_key = None
        self.username = None
        self.commands = {
            "/register": 3,  # command + username + password
            "/login": 3,  # command + username + password
            "/chat": 2,  # command + username
            "/accept": 1,  # just the command
            "/exit": 1,  # just the command
        }
        print("Initializing Client...")
        # Receive DH parameters from server
        parameters_bytes = self.client.recv(4096)
        self.parameters = serialization.load_pem_parameters(
            parameters_bytes, backend=default_backend()
        )
        print("Connected to server! Type /help for available commands.")
        threading.Thread(target=self.receive_messages).start()

    def hash_password(self, password):
        # Hash password on client side
        return hashlib.sha256(password.encode()).hexdigest()

    def encrypt_message(self, message):
        try:
            # Create AES-GCM cipher
            aesgcm = AESGCM(self.session_key)

            # Generate nonce
            nonce = os.urandom(12)

            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

            # Combine nonce and ciphertext and encode
            return base64.b64encode(nonce + ciphertext).decode("utf-8")
        except Exception as e:
            print(f"Error encrypting message: {e}")
            return None

    def decrypt_message(self, encrypted_message):
        try:
            # Decode the message
            encrypted_data = base64.b64decode(encrypted_message)

            # Extract nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            aesgcm = AESGCM(self.session_key)

            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return None

    def receive_messages(self):
        while True:
            try:
                message = self.client.recv(4096).decode("utf-8")
                if not message:
                    break
                # Check for special messages
                if message.startswith(
                    (
                        "ERROR:",
                        "REGISTERED:",
                        "LOGGED_IN:",
                        "CHAT_ENDED:",
                        "REQUEST_SENT:",
                    )
                ):
                    print(f"\n{message}")
                    if message.startswith("LOGGED_IN:"):
                        self.username = message.split()[1].strip(".")
                    if message.startswith("CHAT_ENDED:") or message.startswith("/exit"):
                        self.in_chat = False
                        self.session_key = None
                    continue
                # Try to parse message as JSON
                try:
                    data = json.loads(message)
                    if data["type"] == "chat_request":
                        print(f"\nChat request from {data['from']}")
                        other_public_key_bytes = base64.b64decode(data["public_key"])
                        self.other_public_key = serialization.load_pem_public_key(
                            other_public_key_bytes, backend=default_backend()
                        )
                        print("Type /accept to start chatting")
                    elif data["type"] == "chat_accepted":
                        print("\nChat request accepted!")
                        other_public_key_bytes = base64.b64decode(data["public_key"])
                        other_public_key = serialization.load_pem_public_key(
                            other_public_key_bytes, backend=default_backend()
                        )
                        shared_key = self.private_key.exchange(other_public_key)
                        kdf = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=None,
                            info=b"handshake data",
                            backend=default_backend(),
                        )
                        self.session_key = kdf.derive(shared_key)
                        self.in_chat = True
                        print("\nSecure chat session established!")
                    continue
                except json.JSONDecodeError:
                    pass

                # Handle encrypted messages during chat
                if self.in_chat and self.session_key:
                    try:
                        decrypted_message = self.decrypt_message(message)
                        if decrypted_message:
                            print(f"\nReceived: {decrypted_message}")
                    except Exception as e:
                        print(f"\nError decrypting message: {e}")

            except Exception as e:
                print(f"\nError receiving message: {e}")
                break

    def show_help(self):
        help_text = """
Available commands:
    /register <username> <password> - Create a new account
    /login <username> <password>    - Log in to existing account
    /chat <username>                - Request to chat with a user
    /accept                         - Accept a chat request
    /exit                           - Exit chat session
    /help                           - Show this help message
        """
        print(help_text)

    def validate_command(self, command_parts):
        if not command_parts:
            return False, "Please enter a command. Type /help for available commands."

        command = command_parts[0]
        if command == "/help":
            self.show_help()
            return False, None

        if command not in self.commands:
            return (
                False,
                f"Invalid command '{command}'. Type /help for available commands.",
            )

        expected_args = self.commands[command]
        if len(command_parts) < expected_args:
            if command in ["/register", "/login"]:
                return False, f"Usage: {command} <username> <password>"
            elif command == "/chat":
                return False, f"Usage: {command} <username>"
            else:
                return False, f"Invalid number of arguments for {command}"

        return True, None

    def process_command(self, command):
        if not command.strip():
            return None
        if command == "/exit":
            return json.dumps({
                "command": "/exit",
                "current_username": self.username
            })
        parts = command.split()
        valid, error_message = self.validate_command(parts)

        if not valid:
            if error_message:
                print(error_message)
            return None

        command_name = parts[0]

        if command_name == "/register" or command_name == "/login":
            username = parts[1]
            password = parts[2]
            hashed_password = self.hash_password(password)
            return f"{command_name} {username} {hashed_password}"
        elif command_name == "/chat":
            target_username = parts[1]
            # Generate private key using server's parameters
            self.private_key = self.parameters.generate_private_key()
            public_key = self.private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_key_b64 = base64.b64encode(public_bytes).decode("utf-8")
            return json.dumps(
                {
                    "command": "/chat",
                    "target_user": target_username,
                    "public_key": public_key_b64,
                }
            )
        elif command_name == "/accept":
            # Generate private key using server's parameters
            self.private_key = self.parameters.generate_private_key()
            public_key = self.private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_key_b64 = base64.b64encode(public_bytes).decode("utf-8")

            # Compute shared key
            shared_key = self.private_key.exchange(self.other_public_key)
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"handshake data",
                backend=default_backend(),
            )
            self.session_key = kdf.derive(shared_key)
            self.in_chat = True
            return json.dumps({"command": "/accept", "public_key": public_key_b64})
        else:
            return command

    def send_message(self, message):
        if not message:
            return

        try:
            if self.in_chat and self.session_key and not message.startswith("/"):
                encrypted_message = self.encrypt_message(message)
                if encrypted_message:
                    self.client.send(encrypted_message.encode("utf-8"))
            else:
                # Process commands
                processed_message = self.process_command(message)
                if processed_message:
                    self.client.send(processed_message.encode("utf-8"))
                    if processed_message.startswith("{\"command\": \"/exit"):
                        print("\nExited chat session")
                        self.in_chat = False
                        self.session_key = None
        except Exception as e:
            print(f"Error sending message: {e}")

    def start(self):
        # Show available commands on startup
        self.show_help()  
        while True:
            try:
                prompt = "#MSG: " if self.in_chat else "#CMD: "
                command = input(prompt).strip()
                self.send_message(command)
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
                print("Please try again or type /help for available commands.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure chat application with end-to-end encryption.")
    parser.add_argument("-s", "--server", action="store_true", help="Start the server.")
    parser.add_argument("-c","--client",type=str,help="Start the client and connect to server (format: server_address:port).",)
    parser.add_argument("-p", "--port", type=int, default=5000, help="Port to use (default: 5000).")
    args = parser.parse_args()

    if args.server:
        server = SecureChatServer(port=args.port)
        server.start()
    elif args.client:
        host, port = args.client.split(":")
        client = SecureChatClient(host, int(port))
        client.start()
    else:
        print(
            "Invalid arguments. Use -s to start the server or -c to start the client."
        )
