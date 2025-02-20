import paramiko  # SSH protocol library for handling SSH connections
import socket    # For creating the network socket, allowing my honeypot to create a server that listens for incoming SSH connections
import threading # To handle multiple connections at the same time
import os # Helps me to add the headers to the csv file
import csv # Changed from TXT to CSV for better layout which can be parsed through easier for my dashboard implementation.
from datetime import datetime # Date and Time for the attacks for more accurate information
import requests # To fetch geo locaton data

# --- Configuration Settings ---
HOST = "0.0.0.0"  # Listens on all network interfaces accepting all and any connections
PORT = 2222       # The honeypot will listen on this port for testing purposes. When deployed in  a real world environment I will switch to port 22 (SSH runs on port 22 which will attract real attackers)
LOG_FILE = "honeypot_logs.csv"  # Creating the file where the attacker's attempts are recorded

# Generate a fake SSH host key (RSA 2048-bit) to simulate a real SSH server
host_key = paramiko.RSAKey.generate(2048)

# --- Function to Log Attacker Attempts ---
def get_geolocation(ip):
    """Fetch geolocation data for the attacker's IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data["status"] == "fail":
            return "Unknown", "Unknown", 0, 0  # If lookup fails, return placeholders

        return data["country"], data["city"], data["lat"], data["lon"]
    except Exception as e:
        print(f"[ERROR] Geolocation lookup failed for {ip}: {e}")
        return "Unknown", "Unknown", 0, 0

def log_attempt(ip, username, password):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Fetch geolocation details
    country, city, lat, lon = get_geolocation(ip)

    # Check if file exists and is empty, then write headers
    file_exists = os.path.isfile(LOG_FILE)
    is_empty = os.stat(LOG_FILE).st_size == 0 if file_exists else True

    with open(LOG_FILE, "a", newline="") as log:
        writer = csv.writer(log)
        
        # Write headers if file is newly created or empty
        if is_empty:
            writer.writerow(["Timestamp", "IP", "Username", "Password", "Country", "City", "Latitude", "Longitude"])
        
        # Write the actual log entry
        writer.writerow([timestamp, ip, username, password, country, city, lat, lon])

    print(f"[!] ATTEMPT LOGGED: {timestamp} | IP={ip}, Username={username}, Password={password}, Location={city}, {country}")


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
        
        if username == "root" and password == "root":
            print(f"[!] ATTACKER LOGGED IN AS ROOT from {self.client_ip}")
            return paramiko.AUTH_SUCCESSFUL  # Grant access if root/root is entered
        
        return paramiko.AUTH_FAILED  # Otherwise, reject authentication
        
    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True  # Allow shell access

    def check_channel_exec_request(self, channel, command):
        return True  # Allow execution of fake commands

# --- Function to Simulate a fake system ---
def handle_fake_shell(channel):
    """
    Simulate a fake Linux shell for the attacker.
    """
    channel.send("\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-43-generic x86_64)\n")
    channel.send("root@honeypot:~# ")  # Fake prompt

    fake_filesystem = {
        "/root": ["secret.txt", "id_rsa", "bash_history"],
        "/etc": ["passwd", "shadow", "hosts"],
        "/home/user": ["documents", "downloads", "ssh_keys"],
    }

    while True:
        command = channel.recv(1024).decode("utf-8").strip()

        if command.lower() in ["exit", "logout"]:
            channel.send("\nLogout successful.\n")
            break

        elif command.startswith("ls"):
            path = command[3:].strip() or "/root"
            if path in fake_filesystem:
                channel.send("  ".join(fake_filesystem[path]) + "\n")
            else:
                channel.send(f"ls: cannot access '{path}': No such file or directory\n")

        elif command.startswith("cd"):
            channel.send("\n")  # Just mimics CD without actually changing directories

        elif command.startswith("cat"):
            file = command[4:].strip()
            if file in ["id_rsa", "shadow"]:
                channel.send("Permission denied\n")
            else:
                channel.send(f"Fake contents of {file}\n")

        elif command:
            channel.send(f"bash: {command}: command not found\n")

        channel.send("root@honeypot:~# ")  # Repeat fake prompt
        
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
            
         # Wait for authentication
            chan = transport.accept(20)
            if chan is None:
                continue

            handle_fake_shell(chan)  # Start fake shell session

        except Exception as e:
            print(f"[ERROR] SSH session error: {e}")# Print error message (debugging) 
 
# --- Run the Honeypot ---
if __name__ == "__main__":
    start_honeypot()  # Start the SSH honeypot when the script is run
    
