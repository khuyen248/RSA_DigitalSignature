import os
import threading
import socket
import hashlib
from flask import Flask, request, send_from_directory, jsonify
from flask.templating import render_template_string # Import this for rendering string templates
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here' # Change this in production
socketio = SocketIO(app, cors_allowed_origins="*") 

UPLOAD_FOLDER = 'received_files'
KEYS_FOLDER = 'keys'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

# --- Global Variables for Server/Client State and Keys ---
server_running = False
server_socket_instance = None
private_key = None
public_key = None
connected_clients = {}

# DI CHUYỂN PHẦN NÀY LÊN ĐÂY
def log_message(message):
    socketio.emit('log_message', message)
    print(message) 

# --- HTML Content (Nhúng trực tiếp vào đây) ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ứng dụng Truyền File Chữ Ký Số (Web)</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4;background: linear-gradient(to bottom, #B0E1FA, #E8BDDB); color: #333; }
        .container { max-width: 900px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #0056b3; }
        .frame { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; background-color: #fafafa; }
        .frame legend { font-weight: bold; color: #0056b3; padding: 0 5px; }
        .form-group { margin-bottom: 10px; display: flex; align-items: center; }
        .form-group label { flex: 0 0 150px; margin-right: 10px; text-align: right; }
        .form-group input[type="text"], .form-group input[type="number"], .form-group input[type="file"] { flex: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        .form-group button { padding: 8px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }
        .form-group button:hover { background-color: #0056b3; }
        .form-group button:disabled { background-color: #cccccc; cursor: not-allowed; }
        .log-output { background-color: #e9e9e9; border: 1px solid #ccc; padding: 10px; max-height: 200px; overflow-y: scroll; border-radius: 4px; font-family: monospace; font-size: 0.9em; white-space: pre-wrap; word-wrap: break-word; }
        .status-message { padding: 8px; margin-bottom: 10px; border-radius: 4px; }
        .status-info { background-color: #e0f7fa; border: 1px solid #b2ebf2; color: #00796b; }
        .status-success { background-color: #e8f5e9; border: 1px solid #c8e6c9; color: #388e3c; }
        .status-warning { background-color: #fffde7; border: 1px solid #fff59d; color: #fbc02d; }
        .status-error { background-color: #ffebee; border: 1px solid #ffcdd2; color: #d32f2f; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Ứng dụng Truyền File Chữ Ký Số</h1>

        <fieldset class="frame">
            <legend>Server Info</legend>
            <div class="form-group">
                <label for="serverIp">Set IP Server:</label>
                <input type="text" id="serverIp" value="0.0.0.0">
            </div>
            <div class="form-group">
                <label for="serverPort">Set Port:</label>
                <input type="number" id="serverPort" value="8889">
            </div>
            <div class="form-group">
                <button id="startServerBtn">Connect (Start Server)</button>
                <button id="stopServerBtn" disabled>Disconnect (Stop Server)</button>
            </div>
            <div id="serverStatus" class="status-message status-info">Server Status: Not running</div>
        </fieldset>

        <fieldset class="frame">
            <legend>Client Info</legend>
            <div class="form-group">
                <label for="clientIp">Server IP:</label>
                <input type="text" id="clientIp" value="127.0.0.1">
            </div>
            <div class="form-group">
                <label for="clientPort">Server Port:</label>
                <input type="number" id="clientPort" value="8889">
            </div>
            <div class="form-group">
                <label for="fileInput">Select File:</label>
                <input type="file" id="fileInput">
            </div>
            <div class="form-group">
                <button id="sendFileBtn">Send File</button>
            </div>
            <div id="clientStatus" class="status-message status-info">Client Status: Ready</div>
        </fieldset>

        <fieldset class="frame">
            <legend>App Settings</legend>
            <div class="form-group">
                <label for="segmentSize">Segment Size (Bytes):</label>
                <input type="number" id="segmentSize" value="65536">
            </div>
            <div class="form-group">
                <label for="numConnections">Number of Connections:</label>
                <input type="number" id="numConnections" value="1" disabled title="Multi-connection not implemented in this demo">
            </div>
            <div class="form-group">
                <button id="applySettingsBtn">Apply Settings</button>
            </div>
        </fieldset>

        <fieldset class="frame">
            <legend>Log Output</legend>
            <div id="logOutput" class="log-output"></div>
        </fieldset>
    </div>

    <script>
        var socket = io();

        // --- UI Elements ---
        const serverIpInput = document.getElementById('serverIp');
        const serverPortInput = document.getElementById('serverPort');
        const startServerBtn = document.getElementById('startServerBtn');
        const stopServerBtn = document.getElementById('stopServerBtn');
        const serverStatusDiv = document.getElementById('serverStatus');

        const clientIpInput = document.getElementById('clientIp');
        const clientPortInput = document.getElementById('clientPort');
        const fileInput = document.getElementById('fileInput');
        const sendFileBtn = document.getElementById('sendFileBtn');
        const clientStatusDiv = document.getElementById('clientStatus');

        const segmentSizeInput = document.getElementById('segmentSize');
        const numConnectionsInput = document.getElementById('numConnections');
        const applySettingsBtn = document.getElementById('applySettingsBtn');

        const logOutputDiv = document.getElementById('logOutput');

        // --- Socket.IO Event Handlers ---
        socket.on('connect', function() {
            logMessage('Connected to Flask-SocketIO server.');
        });

        socket.on('log_message', function(msg) {
            logMessage(msg);
        });

        socket.on('server_status', function(data) {
            updateStatus(serverStatusDiv, data.message, data.type);
            if (data.type === 'info' && data.message.includes('Server started')) {
                startServerBtn.disabled = true;
                stopServerBtn.disabled = false;
            } else if (data.type === 'info' && data.message.includes('Server stopped')) {
                startServerBtn.disabled = false;
                stopServerBtn.disabled = true;
            }
        });

        socket.on('client_status', function(data) {
            updateStatus(clientStatusDiv, data.message, data.type);
            if (data.type === 'info' && data.message.includes('Initiated sending')) {
                sendFileBtn.disabled = true;
            } else if (data.type === 'success' || data.type === 'error') {
                sendFileBtn.disabled = false;
            }
        });

        // --- Utility Functions ---
        function logMessage(message) {
            const now = new Date();
            const timestamp = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
            logOutputDiv.innerHTML += `[${timestamp}] ${message}\n`;
            logOutputDiv.scrollTop = logOutputDiv.scrollHeight; // Auto-scroll to bottom
        }

        function updateStatus(div, message, type) {
            div.textContent = message;
            div.className = `status-message status-${type}`;
        }

        // --- Button Event Listeners ---
        startServerBtn.addEventListener('click', function() {
            const ip = serverIpInput.value;
            const port = parseInt(serverPortInput.value);
            if (!ip || isNaN(port)) {
                alert("Please enter valid IP and Port for server.");
                return;
            }
            socket.emit('start_server', { ip: ip, port: port });
        });

        stopServerBtn.addEventListener('click', function() {
            socket.emit('stop_server');
        });

        sendFileBtn.addEventListener('click', function() {
            const ip = clientIpInput.value;
            const port = parseInt(clientPortInput.value);
            const segmentSize = parseInt(segmentSizeInput.value);
            const selectedFile = fileInput.files[0];

            if (!ip || isNaN(port) || !selectedFile) {
                alert("Please enter valid Server IP/Port and select a file.");
                return;
            }
            if (isNaN(segmentSize) || segmentSize <= 0) {
                alert("Please enter a valid positive segment size.");
                return;
            }

            const reader = new FileReader();
            reader.onload = function(event) {
                const fileData = event.target.result; // This will be ArrayBuffer
                socket.emit('send_file', {
                    ip: ip,
                    port: port,
                    file_name: selectedFile.name,
                    file_data: new Uint8Array(fileData), // Convert ArrayBuffer to Uint8Array for Socket.IO
                    segment_size: segmentSize
                });
            };
            reader.readAsArrayBuffer(selectedFile); // Read file as ArrayBuffer
        });

        applySettingsBtn.addEventListener('click', function() {
            try {
                const segmentSize = parseInt(segmentSizeInput.value);
                const numConnections = parseInt(numConnectionsInput.value);
                if (isNaN(segmentSize) || segmentSize <= 0 || isNaN(numConnections) || numConnections <= 0) {
                    alert("Values for settings must be positive numbers.");
                    return;
                }
                logMessage(`Settings applied: Segment Size = ${segmentSize} bytes, Number of Connections = ${numConnections}`);
                alert("Settings applied successfully!");
            } catch (e) {
                alert(`Invalid input for settings: ${e.message}`);
                logMessage(`Error applying settings: ${e.message}`);
            }
        });

        // Initialize button states
        window.onload = function() {
            startServerBtn.disabled = false;
            stopServerBtn.disabled = true;
            sendFileBtn.disabled = false;
        };

    </script>
</body>
</html>
"""

# --- Key Management Functions ---
def generate_and_save_keys():
    global private_key, public_key
    key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
    pub_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")

    if os.path.exists(key_path) and os.path.exists(pub_key_path):
        try:
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None, # For demo, no password. Use password in production.
                    backend=default_backend()
                )
            with open(pub_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            log_message("Loaded existing RSA key pair.")
        except Exception as e:
            log_message(f"Error loading existing keys: {e}. Generating new keys.")
            private_key = None # Reset to generate new ones
    
    if private_key is None: # If not loaded or error during loading
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        with open(key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption() # Use a strong encryption in production
                )
            )
        with open(pub_key_path, "wb") as key_file:
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        log_message("Generated and saved new RSA key pair.")

# Generate/Load keys on app startup
generate_and_save_keys() # Giờ thì hàm log_message đã được định nghĩa khi hàm này được gọi.

# --- Server Logic (Separate Thread) ---
def handle_incoming_client(conn, addr):
    log_message(f"[Server] Connected by {addr}")
    try:
        # Receive file name size and name (fixed size header)
        # We expect a 10-byte string representing the length of the filename
        file_name_size_str = conn.recv(10).decode().strip()
        if not file_name_size_str: raise ConnectionError("Did not receive file name size.")
        file_name_size = int(file_name_size_str)
        file_name = conn.recv(file_name_size).decode()

        # Receive file size (fixed size header)
        # We expect a 20-byte string representing the total file size
        file_size_str = conn.recv(20).decode().strip()
        if not file_size_str: raise ConnectionError("Did not receive file size.")
        file_size = int(file_size_str)

        # Receive digital signature size and signature (fixed size header)
        # We expect a 10-byte string representing the length of the signature
        signature_size_str = conn.recv(10).decode().strip()
        if not signature_size_str: raise ConnectionError("Did not receive signature size.")
        signature_size = int(signature_size_str)
        digital_signature = conn.recv(signature_size)

        log_message(f"[Server] Receiving file '{file_name}' ({file_size} bytes) with signature ({signature_size} bytes) from {addr}...")

        received_data = b""
        temp_file_path = os.path.join(UPLOAD_FOLDER, f"received_{secure_filename(file_name)}")
        bytes_received_count = 0
        with open(temp_file_path, "wb") as f:
            while bytes_received_count < file_size:
                data = conn.recv(65536) # Using a default segment size for server here
                if not data:
                    break # Client disconnected
                f.write(data)
                received_data += data
                bytes_received_count += len(data)

        if bytes_received_count < file_size:
            log_message(f"[Server] Incomplete file transfer for '{file_name}'. Expected {file_size}, got {bytes_received_count}.")
            # Clean up incomplete file
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            # Emit to the specific client that sent the file (if possible to track, or just all clients)
            socketio.emit('server_status', {'message': f"Transfer of '{file_name}' from {addr} Incomplete!", 'type': 'warning'})
            return

        log_message(f"[Server] File '{file_name}' received successfully. Verifying signature...")

        # Verify digital signature
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(received_data)
        digest = hasher.finalize()

        try:
            # In a real application, you'd load the sender's public key
            # from their certificate or a trusted source (e.g., from a CA or a registered user's key).
            # For this demo, we're using the global public_key generated on startup,
            # implying the sender is also 'this server' or trusted by it.
            public_key.verify( # Use the server's public key to verify (assuming it's also the client's public key for demo)
                digital_signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            log_message(f"[Server] Digital signature for '{file_name}' from {addr} is VALID.")
            socketio.emit('server_status', {'message': f"Digital signature for '{file_name}' from {addr} is VALID. File saved as {temp_file_path}", 'type': 'success'})
        except Exception as e:
            log_message(f"[Server] Digital signature for '{file_name}' from {addr} is INVALID: {e}")
            socketio.emit('server_status', {'message': f"Digital signature for '{file_name}' from {addr} is INVALID! Error: {e}", 'type': 'error'})
            # Optionally delete corrupted file here
            # os.remove(temp_file_path)

    except ConnectionError as e:
        log_message(f"[Server] Client {addr} disconnected prematurely: {e}")
        socketio.emit('server_status', {'message': f"Client {addr} disconnected: {e}", 'type': 'error'})
    except ValueError as e:
        log_message(f"[Server] Data format error from {addr}: {e}")
        socketio.emit('server_status', {'message': f"Data format error from {addr}: {e}", 'type': 'error'})
    except Exception as e:
        log_message(f"[Server] General error handling client {addr}: {e}")
        socketio.emit('server_status', {'message': f"Error handling client {addr}: {e}", 'type': 'error'})
    finally:
        conn.close()
        log_message(f"[Server] Connection with {addr} closed.")

def run_server(host, port):
    global server_socket_instance, server_running
    try:
        server_socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket_instance.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse address
        server_socket_instance.bind((host, port))
        server_socket_instance.listen(5)
        server_running = True
        log_message(f"[Server] Listening on {host}:{port}")
        socketio.emit('server_status', {'message': f"Server started on {host}:{port}", 'type': 'info'})

        while server_running:
            try:
                conn, addr = server_socket_instance.accept()
                client_handler = threading.Thread(target=handle_incoming_client, args=(conn, addr), daemon=True)
                client_handler.start()
            except OSError as e:
                if server_running: # Only log if not explicitly stopped
                    log_message(f"[Server] Error accepting client connection: {e}")
                break # Break from loop if server socket is closed (due to shutdown or manual stop)
            except Exception as e:
                log_message(f"[Server] General error in server accept loop: {e}")
                break

    except Exception as e:
        log_message(f"[Server] Failed to start server: {e}")
        socketio.emit('server_status', {'message': f"Failed to start server: {e}", 'type': 'error'})
    finally:
        if server_socket_instance:
            server_socket_instance.close()
            server_socket_instance = None
        server_running = False
        log_message("[Server] Server thread stopped.")
        socketio.emit('server_status', {'message': "Server stopped", 'type': 'info'})

# --- Client Logic (Websocket Triggered) ---
def send_file_client_thread(host, port, file_path, segment_size):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        log_message(f"[Client] Successfully connected to server {host}:{port}")

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Generate digital signature
        with open(file_path, "rb") as f:
            file_content = f.read()

        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(file_content)
        digest = hasher.finalize()

        digital_signature = private_key.sign( # Use client's private key to sign
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        log_message("[Client] File content hashed and signed.")

        # Send file info (name, size, signature) - using fixed-length headers
        # Use <10 and <20 for padding to ensure fixed length
        client_socket.sendall(f"{len(file_name):<10}".encode() + file_name.encode())
        client_socket.sendall(f"{file_size:<20}".encode())
        client_socket.sendall(f"{len(digital_signature):<10}".encode() + digital_signature)

        log_message(f"[Client] Sending file '{file_name}' ({file_size} bytes) with signature...")

        # Send file data
        bytes_sent = 0
        with open(file_path, "rb") as f:
            while True:
                bytes_read = f.read(segment_size)
                if not bytes_read:
                    break # End of file
                client_socket.sendall(bytes_read)
                bytes_sent += len(bytes_read)
                # Emit progress (optional)
                # socketio.emit('client_progress', {'sent': bytes_sent, 'total': file_size})

        log_message(f"[Client] File '{file_name}' sent successfully ({bytes_sent} bytes).")
        socketio.emit('client_status', {'message': f"File '{file_name}' sent successfully!", 'type': 'success'})

    except ConnectionRefusedError:
        log_message("[Client] Connection error: Server is not running or refused connection.")
        socketio.emit('client_status', {'message': "Server is not running or connection refused.", 'type': 'error'})
    except FileNotFoundError:
        log_message(f"[Client] File not found: {file_path}")
        socketio.emit('client_status', {'message': "Selected file not found on server.", 'type': 'error'})
    except Exception as e:
        log_message(f"[Client] Error during file transfer: {e}")
        socketio.emit('client_status', {'message': f"Error during file transfer: {e}", 'type': 'error'})
    finally:
        if 'client_socket' in locals() and client_socket:
            client_socket.close()
            log_message("[Client] Client socket closed.")
        # Clean up the temporary file after sending
        if os.path.exists(file_path) and file_path.startswith(os.path.join(UPLOAD_FOLDER, "uploaded_")):
             os.remove(file_path)
             log_message(f"[Client] Cleaned up temporary file: {file_path}")

# --- Flask Routes and SocketIO Events ---
@app.route('/')
def index():
    return render_template_string(HTML_CONTENT)

@socketio.on('start_server')
def handle_start_server(data):
    global server_running
    if server_running:
        log_message("[Server] Server is already running.")
        socketio.emit('server_status', {'message': "Server is already running.", 'type': 'warning'})
        return

    host = data['ip']
    port = int(data['port'])

    server_thread = threading.Thread(target=run_server, args=(host, port), daemon=True)
    server_thread.start()

@socketio.on('stop_server')
def handle_stop_server():
    global server_running, server_socket_instance
    if server_socket_instance and server_running:
        try:
            server_running = False # Signal the server thread to stop
            # To unblock server_socket_instance.accept(), create a dummy connection
            # Use 127.0.0.1 for the dummy connection to ensure it connects to the local server
            current_port = server_socket_instance.getsockname()[1] # Get the actual port server is listening on
            dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy_socket.connect(('127.0.0.1', current_port))
            dummy_socket.close()
            log_message("[Server] Attempting to stop server...")
            socketio.emit('server_status', {'message': "Server stop initiated...", 'type': 'info'})
        except Exception as e:
            log_message(f"[Server] Error initiating server stop: {e}")
            socketio.emit('server_status', {'message': f"Error stopping server: {e}", 'type': 'error'})
    else:
        log_message("[Server] Server is not running.")
        socketio.emit('server_status', {'message': "Server is not running.", 'type': 'warning'})

@socketio.on('send_file')
def handle_send_file(data):
    file_data_bytes = data['file_data'] # This is already bytes from JS Uint8Array
    file_name = data['file_name']
    host = data['ip']
    port = int(data['port'])
    segment_size = int(data['segment_size'])

    # Save the uploaded file temporarily on the server-side
    # Add a prefix to distinguish client-uploaded files from received files
    temp_file_path = os.path.join(UPLOAD_FOLDER, f"uploaded_{secure_filename(file_name)}")
    with open(temp_file_path, "wb") as f:
        f.write(file_data_bytes) # file_data_bytes is already bytes

    log_message(f"Received file '{file_name}' from web client for sending to TCP server.")

    # Start sending file in a new thread
    client_thread = threading.Thread(target=send_file_client_thread, args=(host, port, temp_file_path, segment_size), daemon=True)
    client_thread.start()
    socketio.emit('client_status', {'message': f"Initiated sending of '{file_name}' to {host}:{port}", 'type': 'info'})

# --- Start Flask App ---
if __name__ == '__main__':
    # Use 0.0.0.0 to make it accessible from other devices on the network
    # For local testing, 127.0.0.1 is fine.
    print("Starting Flask web server...")
    print("Access the application at: http://127.0.0.1:5000/")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)