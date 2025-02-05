import paramiko  # SSH protocol library for handling SSH connections
import socket    # For creating the network socket, allowing my honeypot to create a server that listens for incoming SSH connections
import threading # To handle multiple connections at the same time
import os # Helps me to add the headers to the csv file
import csv # Changed from TXT to CSV for better layout which can be parsed through easier for my dashboard implementation.
from datetime import datetime # Date and Time for the attacks for more accurate information

# --- Configuration Settings ---
HOST = "0.0.0.0"  # Listens on all network interfaces accepting all and any connections
PORT = 2222       # The honeypot will listen on this port for testing purposes. When deployed in  a real world environment I will switch to port 22 (SSH runs on port 22 which will attract real attackers)
LOG_FILE = "honeypot_logs.csv"  # Creating the file where the attacker's attempts are recorded

# Generate a fake SSH host key (RSA 2048-bit) to simulate a real SSH server
host_key = paramiko.RSAKey.generate(2048)

# --- Function to Log Attacker Attempts ---
def log_attempt(ip, username, password):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if file exists and is empty, then write headers
    file_exists = os.path.isfile(LOG_FILE)
    is_empty = os.stat(LOG_FILE).st_size == 0 if file_exists else True

    with open(LOG_FILE, "a", newline="") as log:
        writer = csv.writer(log)
        
        # Write headers if file is newly created or empty
        if is_empty:
            writer.writerow(["Timestamp", "IP", "Username", "Password"])
        
        # Write the actual log entry
        writer.writerow([timestamp, ip, username, password])

    print(f"[!] ATTEMPT LOGGED: {timestamp} | IP={ip}, Username={username}, Password={password}")


# --- SSH Honeypot Server Interface ---
class SSHHoneypot(paramiko.ServerInterface):
    """
    This class defines the SSH server behavior. It fakes an authentication process but never grants access.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip  # Store attacker's IP address

    def check_auth_password(self, username, password):
        """
        This function is called when an attacker tries to log in.
        Instead of allowing access, it logs the credentials and always rejects them.
        """
        log_attempt(self.client_ip, username, password)  # Save the login attempt and add it to the log
        return paramiko.AUTH_FAILED  # Always reject authentication

# --- Function to Start the Honeypot ---
def start_honeypot():
    """
    This function sets up the fake SSH server, listens for connections,
    and handles attacker interactions.
    """
    # Step 1: Create a network socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 + TCP socket
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reusing the address immediately after closing

    # Step 2: Bind the socket to the specified host and port
    server.bind((HOST, PORT))  # The honeypot will listen on HOST:PORT

    # Step 3: Start listening for incoming SSH connections
    server.listen(10)  # Allows up to 10  in the queue before refusing new ones
    print(f"[*] SSH Honeypot is now listening on {HOST}:{PORT}...")

    while True:  # Infinite loop to make sure the honeypot stays running
        client, addr = server.accept()  # Accept incoming connection
        print(f"[!] Connection received from {addr[0]}")  # Display attacker's IP

        # Step 4: Set up SSH transport over the network socket
        transport = paramiko.Transport(client)  # Create an SSH transport layer
        transport.add_server_key(host_key)  # Assign the fake SSH server key

        # Step 5: Handle authentication using the SSHHoneypot class
        server_handler = SSHHoneypot(addr[0])  # Pass attacker's IP to the honeypot handler

        try:
            transport.start_server(server=server_handler)  # Start the fake SSH server
        except Exception as e:
            print(f"[ERROR] Failed to start SSH transport: {e}")  # Print error message (debugging) 

# --- Run the Honeypot ---
if __name__ == "__main__":
    start_honeypot()  # Start the SSH honeypot when the script is run
