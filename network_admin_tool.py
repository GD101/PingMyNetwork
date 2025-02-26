import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import subprocess
import re
import pandas as pd
import socket
import time
import os
import json
import paramiko
import netmiko
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
import logging
import datetime
from ipaddress import IPv4Network, IPv4Address

class NetworkAdminTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Administrator Tool")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Set theme and styles
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use "clam" for a more modern look
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 10), background="#f0f0f0")
        self.style.configure("TNotebook", background="#f0f0f0")
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"))
        
        # Variables
        self.devices = []
        self.credentials = {"username": "", "password": "", "enable_secret": ""}
        self.log_enabled = tk.BooleanVar(value=True)
        self.log_file = os.path.join(os.path.expanduser("~"), "network_admin_logs.txt")
        
        # Initialize logging
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.devices_tab = ttk.Frame(self.notebook)
        self.operations_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)  # New About tab
        
        self.notebook.add(self.devices_tab, text="Devices")
        self.notebook.add(self.operations_tab, text="Operations")
        self.notebook.add(self.logs_tab, text="Logs")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.about_tab, text="About")  # Add the About tab
        
        # Setup each tab
        self._setup_devices_tab()
        self._setup_operations_tab()
        self._setup_logs_tab()
        self._setup_settings_tab()
        self._setup_about_tab() # Setup the About tab
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Load settings if they exist
        self._load_settings()
        
        # Log startup
        if self.log_enabled.get():
            logging.info("Application started")
    
    def _setup_devices_tab(self):
        devices_frame = ttk.Frame(self.devices_tab, padding="10")
        devices_frame.pack(fill=tk.BOTH, expand=True)
        
        # Split into left and right panes
        left_frame = ttk.Frame(devices_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        right_frame = ttk.Frame(devices_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Left frame - Device list
        list_label = ttk.Label(left_frame, text="Network Devices")
        list_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.device_tree = ttk.Treeview(left_frame, columns=("IP", "Type", "Status"), show="headings")
        self.device_tree.heading("IP", text="IP Address")
        self.device_tree.heading("Type", text="Device Type")
        self.device_tree.heading("Status", text="Status")
        self.device_tree.column("IP", width=150)
        self.device_tree.column("Type", width=100)
        self.device_tree.column("Status", width=80)
        self.device_tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.device_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        # Device list buttons
        device_btn_frame = ttk.Frame(left_frame)
        device_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(device_btn_frame, text="Add Device", command=self._add_device_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(device_btn_frame, text="Remove", command=self._remove_selected_device).pack(side=tk.LEFT, padx=2)
        ttk.Button(device_btn_frame, text="Import from Excel", command=self._import_from_excel).pack(side=tk.LEFT, padx=2)
        ttk.Button(device_btn_frame, text="Ping All", command=lambda: self._run_operation("ping_all")).pack(side=tk.LEFT, padx=2)
        
        # Right frame - Device details
        details_label = ttk.Label(right_frame, text="Device Details")
        details_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.device_details = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, height=15)
        self.device_details.pack(fill=tk.BOTH, expand=True)
        
        # Bind select event
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)
    
    def _setup_operations_tab(self):
        operations_frame = ttk.Frame(self.operations_tab, padding="10")
        operations_frame.pack(fill=tk.BOTH, expand=True)
        
        # Split into left and right panes
        left_frame = ttk.Frame(operations_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        right_frame = ttk.Frame(operations_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Left frame - Operations
        op_label = ttk.Label(left_frame, text="Available Operations")
        op_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Operation buttons frame with grid layout
        op_buttons_frame = ttk.Frame(left_frame)
        op_buttons_frame.pack(fill=tk.BOTH, expand=True)
        
        # Row 1
        ttk.Button(op_buttons_frame, text="Check Temperature", 
                  command=lambda: self._run_operation("check_temperature")).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(op_buttons_frame, text="Find Disconnected Ports", 
                  command=lambda: self._run_operation("find_disconnected_ports")).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Row 2
        ttk.Button(op_buttons_frame, text="Trace Loop", 
                  command=lambda: self._run_operation("trace_loop")).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(op_buttons_frame, text="VLAN Scan", 
                  command=lambda: self._run_operation("vlan_scan")).grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Row 3
        ttk.Button(op_buttons_frame, text="Device Information", 
                  command=lambda: self._run_operation("device_info")).grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(op_buttons_frame, text="Interface Status", 
                  command=lambda: self._run_operation("interface_status")).grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to be same width
        op_buttons_frame.columnconfigure(0, weight=1)
        op_buttons_frame.columnconfigure(1, weight=1)
        
        # Right frame - Operation results
        results_label = ttk.Label(right_frame, text="Operation Results")
        results_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.operation_results = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD)
        self.operation_results.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(right_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
    
    def _setup_logs_tab(self):
        logs_frame = ttk.Frame(self.logs_tab, padding="10")
        logs_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log control frame
        log_control_frame = ttk.Frame(logs_frame)
        log_control_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Checkbutton(log_control_frame, text="Enable Logging", variable=self.log_enabled).pack(side=tk.LEFT)
        ttk.Button(log_control_frame, text="Refresh Logs", command=self._refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_control_frame, text="Clear Logs", command=self._clear_logs).pack(side=tk.LEFT)
        ttk.Button(log_control_frame, text="Export Logs", command=self._export_logs).pack(side=tk.LEFT, padx=5)
        
        # Log display
        self.log_display = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD)
        self.log_display.pack(fill=tk.BOTH, expand=True)
        
        # Load logs
        self._refresh_logs()
    
    def _setup_settings_tab(self):
        settings_frame = ttk.Frame(self.settings_tab, padding="10")
        settings_frame.pack(fill=tk.BOTH, expand=True)
        
        # Credentials frame
        cred_frame = ttk.LabelFrame(settings_frame, text="Default Credentials")
        cred_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_var = tk.StringVar(value=self.credentials["username"])
        ttk.Entry(cred_frame, textvariable=self.username_var).grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_var = tk.StringVar(value=self.credentials["password"])
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        
        ttk.Label(cred_frame, text="Enable Secret:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.enable_var = tk.StringVar(value=self.credentials["enable_secret"])
        ttk.Entry(cred_frame, textvariable=self.enable_var, show="*").grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        
        cred_frame.columnconfigure(1, weight=1)
        
        # Application settings frame
        app_frame = ttk.LabelFrame(settings_frame, text="Application Settings")
        app_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(app_frame, text="Log File Location:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.log_path_var = tk.StringVar(value=self.log_file)
        log_path_entry = ttk.Entry(app_frame, textvariable=self.log_path_var)
        log_path_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(app_frame, text="Browse", command=self._browse_log_path).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(app_frame, text="Timeout (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.timeout_var = tk.IntVar(value=5)
        ttk.Spinbox(app_frame, from_=1, to=60, textvariable=self.timeout_var).grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        
        app_frame.columnconfigure(1, weight=1)
        
        # Actions frame
        actions_frame = ttk.Frame(settings_frame)
        actions_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(actions_frame, text="Save Settings", command=self._save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(actions_frame, text="Reset to Defaults", command=self._reset_settings).pack(side=tk.RIGHT)
    
    def _setup_about_tab(self):
        """Sets up the About tab."""
        about_frame = ttk.Frame(self.about_tab, padding="10")
        about_frame.pack(fill=tk.BOTH, expand=True)

        about_text = """
        Network Administrator Tool

        Author: Glenn Dbritto & Anthropic
        Email: engulya@protonmail.com
        License: It's completely free for use.

        Thanks for using the application!
        """

        about_label = ttk.Label(about_frame, text=about_text, font=("Segoe UI", 12), justify=tk.LEFT)
        about_label.pack(anchor=tk.W, padx=10, pady=10)


    def _add_device_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Network Device")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form frame
        form_frame = ttk.Frame(dialog, padding="10")
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # IP Address
        ttk.Label(form_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ip_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=ip_var).grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        # Device Type
        ttk.Label(form_frame, text="Device Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        type_var = tk.StringVar()
        ttk.Combobox(form_frame, textvariable=type_var, values=["cisco_ios", "cisco_nxos", "juniper", "alcatel_aos"]).grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        
        # Username (if different from default)
        ttk.Label(form_frame, text="Username:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        username_var = tk.StringVar(value=self.credentials["username"])
        ttk.Entry(form_frame, textvariable=username_var).grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        
        # Password (if different from default)
        ttk.Label(form_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        password_var = tk.StringVar(value=self.credentials["password"])
        ttk.Entry(form_frame, textvariable=password_var, show="*").grid(row=3, column=1, sticky="ew", padx=5, pady=5)
        
        # Use default credentials checkbox
        use_defaults_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, text="Use default credentials", variable=use_defaults_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # Configure grid
        form_frame.columnconfigure(1, weight=1)
        
        # Button frame
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, pady=5)
        
        def add_device():
            ip = ip_var.get().strip()
            device_type = type_var.get().strip()
            
            # Basic validation
            if not ip or not device_type:
                messagebox.showerror("Error", "IP Address and Device Type are required")
                return
            
            # Validate IP
            try:
                socket.inet_aton(ip)
            except socket.error:
                messagebox.showerror("Error", "Invalid IP Address format")
                return
            
            # Create device entry
            device = {
                "ip": ip,
                "type": device_type,
                "username": self.credentials["username"] if use_defaults_var.get() else username_var.get(),
                "password": self.credentials["password"] if use_defaults_var.get() else password_var.get(),
                "enable_secret": self.credentials["enable_secret"]
            }
            
            # Add to devices list
            self.devices.append(device)
            
            # Update treeview
            self.device_tree.insert("", tk.END, values=(ip, device_type, "Unknown"))
            
            # Log
            if self.log_enabled.get():
                logging.info(f"Added device: {ip} ({device_type})")
            
            dialog.destroy()
        
        ttk.Button(btn_frame, text="Add", command=add_device).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def _remove_selected_device(self):
        selected = self.device_tree.selection()
        
        if not selected:
            messagebox.showinfo("Info", "No device selected")
            return
        
        for item in selected:
            values = self.device_tree.item(item, "values")
            ip = values[0]
            
            # Remove from devices list
            self.devices = [d for d in self.devices if d["ip"] != ip]
            
            # Remove from treeview
            self.device_tree.delete(item)
            
            # Log
            if self.log_enabled.get():
                logging.info(f"Removed device: {ip}")
    
    def _import_from_excel(self):
        file_path = filedialog.askopenfilename(
            title="Select Excel File",
            filetypes=[("Excel files", "*.xlsx *.xls")]
        )
        
        if not file_path:
            return
        
        try:
            df = pd.read_excel(file_path)
            
            # Check required columns
            required_cols = ["ip", "type"]
            if not all(col in df.columns for col in required_cols):
                messagebox.showerror("Error", f"Excel file must contain these columns: {', '.join(required_cols)}")
                return
            
            # Import devices
            devices_added = 0
            
            for _, row in df.iterrows():
                ip = str(row["ip"]).strip()
                device_type = str(row["type"]).strip()
                
                # Skip invalid entries
                try:
                    socket.inet_aton(ip)
                except socket.error:
                    continue
                
                # Create device entry
                device = {
                    "ip": ip,
                    "type": device_type,
                    "username": self.credentials["username"],
                    "password": self.credentials["password"],
                    "enable_secret": self.credentials["enable_secret"]
                }
                
                # Add to devices list if not already present
                if not any(d["ip"] == ip for d in self.devices):
                    self.devices.append(device)
                    self.device_tree.insert("", tk.END, values=(ip, device_type, "Unknown"))
                    devices_added += 1
            
            # Log
            if self.log_enabled.get():
                logging.info(f"Imported {devices_added} devices from Excel file: {file_path}")
            
            messagebox.showinfo("Import Successful", f"Imported {devices_added} devices")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import Excel file: {str(e)}")
    
    def _on_device_select(self, event):
        selected = self.device_tree.selection()
        
        if not selected:
            return
        
        # Get selected device IP
        values = self.device_tree.item(selected[0], "values")
        ip = values[0]
        
        # Find device in list
        device = next((d for d in self.devices if d["ip"] == ip), None)
        
        if not device:
            return
        
        # Display device details
        self.device_details.delete(1.0, tk.END)
        self.device_details.insert(tk.END, f"IP Address: {device['ip']}\n")
        self.device_details.insert(tk.END, f"Device Type: {device['type']}\n")
        self.device_details.insert(tk.END, f"Username: {device['username']}\n")
        self.device_details.insert(tk.END, f"Password: {'*' * len(device['password'])}\n\n")
        
        # Try to ping the device
        self.device_details.insert(tk.END, "Pinging device... ")
        
        threading.Thread(target=self._ping_device, args=(device["ip"],)).start()
    
    def _ping_device(self, ip):
        """Ping a device and update the device details"""
        try:
            if os.name == 'nt':  # Windows
                ping_cmd = ["ping", "-n", "2", "-w", "1000", ip]
            else:  # Linux/Mac
                ping_cmd = ["ping", "-c", "2", "-W", "1", ip]
            
            result = subprocess.run(ping_cmd, capture_output=True, text=True)
            success = "TTL=" in result.stdout or " 0% packet loss" in result.stdout
            
            # Update UI in main thread
            self.root.after(0, self._update_ping_result, ip, success, result.stdout)
            
        except Exception as e:
            self.root.after(0, self._update_ping_result, ip, False, str(e))
    
    def _update_ping_result(self, ip, success, output):
        # Update device details
        self.device_details.insert(tk.END, "Success\n\n" if success else "Failed\n\n")
        self.device_details.insert(tk.END, "Ping Output:\n")
        self.device_details.insert(tk.END, output)
        
        # Update device status in treeview
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item, "values")
            if values[0] == ip:
                self.device_tree.item(item, values=(values[0], values[1], "Online" if success else "Offline"))
                break
    
    def _run_operation(self, operation_name):
        """Run a network operation in a separate thread"""
        selected = self.device_tree.selection()
        
        if not selected and operation_name != "ping_all":
            messagebox.showinfo("Info", "No device selected")
            return
        
        # Clear results
        self.operation_results.delete(1.0, tk.END)
        self.progress_var.set(0)
        
        # Log operation
        if self.log_enabled.get():
            if operation_name == "ping_all":
                logging.info(f"Running operation: {operation_name} on all devices")
            else:
                selected_ips = [self.device_tree.item(item, "values")[0] for item in selected]
                logging.info(f"Running operation: {operation_name} on devices: {', '.join(selected_ips)}")
        
        # Start operation in a separate thread
        if operation_name == "ping_all":
            threading.Thread(target=self._ping_all_operation).start()
        else:
            # Get selected devices
            devices = []
            for item in selected:
                ip = self.device_tree.item(item, "values")[0]
                device = next((d for d in self.devices if d["ip"] == ip), None)
                if device:
                    devices.append(device)
            
            threading.Thread(target=self._run_device_operation, args=(operation_name, devices)).start()
    
    def _ping_all_operation(self):
        """Ping all devices in the list"""
        if not self.devices:
            self.root.after(0, lambda: messagebox.showinfo("Info", "No devices in the list"))
            return
        
        self.root.after(0, lambda: self.status_var.set("Pinging all devices..."))
        self.root.after(0, lambda: self.operation_results.insert(tk.END, "Pinging all devices...\n\n"))
        
        total_devices = len(self.devices)
        online_devices = 0
        
        for i, device in enumerate(self.devices):
            ip = device["ip"]
            
            # Update progress
            progress = (i / total_devices) * 100
            self.root.after(0, lambda p=progress: self.progress_var.set(p))
            
            try:
                if os.name == 'nt':  # Windows
                    ping_cmd = ["ping", "-n", "2", "-w", "1000", ip]
                else:  # Linux/Mac
                    ping_cmd = ["ping", "-c", "2", "-W", "1", ip]
                
                result = subprocess.run(ping_cmd, capture_output=True, text=True)
                success = "TTL=" in result.stdout or " 0% packet loss" in result.stdout
                
                # Update result
                status = "Online" if success else "Offline"
                self.root.after(0, lambda ip=ip, status=status: self.operation_results.insert(tk.END, f"Device {ip}: {status}\n"))
                
                # Update device status in treeview
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item, "values")
                    if values[0] == ip:
                        self.root.after(0, lambda item=item, values=values, status=status: 
                                        self.device_tree.item(item, values=(values[0], values[1], status)))
                        break
                
                if success:
                    online_devices += 1
                
            except Exception as e:
                self.root.after(0, lambda ip=ip, e=e: self.operation_results.insert(tk.END, f"Device {ip}: Error - {str(e)}\n"))
        
        # Complete progress
        self.root.after(0, lambda: self.progress_var.set(100))
        self.root.after(0, lambda: self.operation_results.insert(tk.END, f"\nComplete: {online_devices} of {total_devices} devices online\n"))
        self.root.after(0, lambda: self.status_var.set("Ready"))
        
        # Log results
        if self.log_enabled.get():
            logging.info(f"Ping all operation complete: {online_devices} of {total_devices} devices online")
    
    def _run_device_operation(self, operation_name, devices):
        """Run a network operation on selected devices"""
        self.root.after(0, lambda: self.status_var.set(f"Running {operation_name}..."))
        
        total_devices = len(devices)
        
        for i, device in enumerate(devices):
            # Update progress
            progress = (i / total_devices) * 100
            self.root.after(0, lambda p=progress: self.progress_var.set(p))
            
            # Run the specific operation
            try:
                result = self._execute_device_operation(operation_name, device)
                
                # Update result in the UI (in the main thread)
                self.root.after(0, lambda d=device, r=result: self._update_operation_result(operation_name, d, r))
                
            except Exception as e:
                error_msg = f"Error executing {operation_name} on {device['ip']}: {str(e)}"
                self.root.after(0, lambda msg=error_msg: self.operation_results.insert(tk.END, msg + "\n\n"))
                
                # Log error
                if self.log_enabled.get():
                    logging.error(error_msg)
        
        # Complete progress
        self.root.after(0, lambda: self.progress_var.set(100))
        self.root.after(0, lambda: self.status_var.set("Ready"))
    
    def _execute_device_operation(self, operation_name, device):
        """Execute a specific network operation on a device"""
        ip = device["ip"]
        device_type = device["type"]
        
        # For demonstration, we'll simulate the operations
        # In a real implementation, you would use netmiko/paramiko to connect to devices
        
        if operation_name == "check_temperature":
            # Simulate checking temperature
            time.sleep(1)  # Simulate operation time
            
            # Return simulated temperature data
            return {
                "temperature": f"{25 + (hash(ip) % 15)}°C",
                "status": "Normal" if hash(ip) % 15 < 10 else "Warning",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        elif operation_name == "find_disconnected_ports":
            # Simulate finding disconnected ports
            time.sleep(1.5)  #
            time.sleep(1.5)  # Simulate operation time
            
            # Return simulated disconnected ports
            ports = []
            for i in range(1, 25):  # Simulate 24 ports
                if (hash(ip) + i) % 5 == 0:  # Randomly mark some ports as disconnected
                    ports.append(f"GigabitEthernet0/{i}")
            
            return {
                "disconnected_ports": ports,
                "total_ports": 24,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        elif operation_name == "trace_loop":
            # Simulate loop tracing
            time.sleep(2)  # Simulate operation time
            
            # Return simulated loop data
            return {
                "loop_detected": (hash(ip) % 10) < 3,  # 30% chance of loop
                "loop_path": [f"192.168.1.{(hash(ip) % 254) + 1}", f"192.168.1.{(hash(ip) % 254) + 2}", ip] if (hash(ip) % 10) < 3 else [],
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        elif operation_name == "vlan_scan":
            # Simulate VLAN scanning
            time.sleep(1.8)  # Simulate operation time
            
            # Return simulated VLAN data
            vlans = []
            for i in range(1, 10):
                if (hash(ip) + i) % 3 == 0:  # Randomly select VLANs
                    vlans.append({
                        "id": i * 10,
                        "name": f"VLAN{i*10}",
                        "status": "active" if (hash(ip) + i) % 5 != 0 else "inactive"
                    })
            
            return {
                "vlans": vlans,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        elif operation_name == "device_info":
            # Simulate getting device information
            time.sleep(1.2)  # Simulate operation time
            
            # Return simulated device information
            model_map = {
                "cisco_ios": "Cisco Catalyst 9300",
                "cisco_nxos": "Cisco Nexus 9000",
                "juniper": "Juniper EX4300",
                "alcatel_aos": "Alcatel-Lucent OmniSwitch 6900"
            }
            
            version_map = {
                "cisco_ios": "16.9.5",
                "cisco_nxos": "9.3(7)",
                "juniper": "20.3R1.9",
                "alcatel_aos": "8.6.1.R01"
            }
            
            return {
                "model": model_map.get(device_type, "Unknown"),
                "os_version": version_map.get(device_type, "Unknown"),
                "serial": f"SN{hash(ip) % 10000:05d}",
                "uptime": f"{(hash(ip) % 365) + 1} days, {(hash(ip) % 24)} hours",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        elif operation_name == "interface_status":
            # Simulate getting interface status
            time.sleep(1.5)  # Simulate operation time
            
            # Return simulated interface status
            interfaces = []
            for i in range(1, 25):  # Simulate 24 interfaces
                status = "up" if (hash(ip) + i) % 4 != 0 else "down"
                interfaces.append({
                    "name": f"GigabitEthernet0/{i}",
                    "status": status,
                    "vlan": (hash(ip) + i) % 10 * 10,
                    "duplex": "full" if status == "up" else "auto",
                    "speed": "1000Mb/s" if status == "up" else "auto"
                })
            
            return {
                "interfaces": interfaces,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        # Default case
        return {"error": "Operation not implemented"}
    
    def _update_operation_result(self, operation_name, device, result):
        """Update the operation results in the UI"""
        self.operation_results.insert(tk.END, f"--- {operation_name.upper()} RESULTS FOR {device['ip']} ---\n")
        
        if operation_name == "check_temperature":
            self.operation_results.insert(tk.END, f"Temperature: {result['temperature']}\n")
            self.operation_results.insert(tk.END, f"Status: {result['status']}\n")
            self.operation_results.insert(tk.END, f"Timestamp: {result['timestamp']}\n\n")
            
        elif operation_name == "find_disconnected_ports":
            self.operation_results.insert(tk.END, f"Total Ports: {result['total_ports']}\n")
            self.operation_results.insert(tk.END, f"Disconnected Ports: {len(result['disconnected_ports'])}\n\n")
            
            if result['disconnected_ports']:
                self.operation_results.insert(tk.END, "Port List:\n")
                for port in result['disconnected_ports']:
                    self.operation_results.insert(tk.END, f"- {port}\n")
            else:
                self.operation_results.insert(tk.END, "No disconnected ports found.\n")
                
            self.operation_results.insert(tk.END, f"\nTimestamp: {result['timestamp']}\n\n")
            
        elif operation_name == "trace_loop":
            if result['loop_detected']:
                self.operation_results.insert(tk.END, "LOOP DETECTED!\n")
                self.operation_results.insert(tk.END, "Loop Path:\n")
                for node in result['loop_path']:
                    self.operation_results.insert(tk.END, f"- {node}\n")
            else:
                self.operation_results.insert(tk.END, "No loops detected.\n")
                
            self.operation_results.insert(tk.END, f"\nTimestamp: {result['timestamp']}\n\n")
            
        elif operation_name == "vlan_scan":
            self.operation_results.insert(tk.END, f"VLANs Found: {len(result['vlans'])}\n\n")
            
            if result['vlans']:
                self.operation_results.insert(tk.END, "VLAN List:\n")
                for vlan in result['vlans']:
                    self.operation_results.insert(tk.END, f"- VLAN {vlan['id']} ({vlan['name']}): {vlan['status']}\n")
            else:
                self.operation_results.insert(tk.END, "No VLANs found.\n")
                
            self.operation_results.insert(tk.END, f"\nTimestamp: {result['timestamp']}\n\n")
            
        elif operation_name == "device_info":
            self.operation_results.insert(tk.END, f"Model: {result['model']}\n")
            self.operation_results.insert(tk.END, f"OS Version: {result['os_version']}\n")
            self.operation_results.insert(tk.END, f"Serial Number: {result['serial']}\n")
            self.operation_results.insert(tk.END, f"Uptime: {result['uptime']}\n")
            self.operation_results.insert(tk.END, f"Timestamp: {result['timestamp']}\n\n")
            
        elif operation_name == "interface_status":
            self.operation_results.insert(tk.END, f"Total Interfaces: {len(result['interfaces'])}\n\n")
            
            # Count up/down interfaces
            up_count = sum(1 for iface in result['interfaces'] if iface['status'] == 'up')
            down_count = len(result['interfaces']) - up_count
            
            self.operation_results.insert(tk.END, f"Up: {up_count}, Down: {down_count}\n\n")
            
            self.operation_results.insert(tk.END, "Interface Status:\n")
            for iface in result['interfaces']:
                self.operation_results.insert(tk.END, f"- {iface['name']}: {iface['status']}, VLAN {iface['vlan']}, {iface['duplex']}, {iface['speed']}\n")
                
            self.operation_results.insert(tk.END, f"\nTimestamp: {result['timestamp']}\n\n")
        
        # Log operation result
        if self.log_enabled.get():
            logging.info(f"Completed {operation_name} on {device['ip']}")
    
    def _refresh_logs(self):
        """Refresh the log display"""
        try:
            with open(self.log_file, "r") as f:
                log_contents = f.read()
                
            self.log_display.delete(1.0, tk.END)
            self.log_display.insert(tk.END, log_contents)
            
            # Auto-scroll to bottom
            self.log_display.see(tk.END)
            
        except Exception as e:
            self.log_display.delete(1.0, tk.END)
            self.log_display.insert(tk.END, f"Error loading logs: {str(e)}")
    
    def _clear_logs(self):
        """Clear the log file"""
        try:
            with open(self.log_file, "w") as f:
                f.write("")
                
            self.log_display.delete(1.0, tk.END)
            self.log_display.insert(tk.END, "Logs cleared.")
            
            # Add startup log entry
            if self.log_enabled.get():
                logging.info("Logs cleared")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
    
    def _export_logs(self):
        """Export logs to a file"""
        file_path = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(self.log_file, "r") as source:
                with open(file_path, "w") as target:
                    target.write(source.read())
                    
            messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")
            
            # Log export
            if self.log_enabled.get():
                logging.info(f"Logs exported to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def _browse_log_path(self):
        """Browse for log file location"""
        file_path = filedialog.asksaveasfilename(
            title="Select Log File Location",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=os.path.basename(self.log_file),
            initialdir=os.path.dirname(self.log_file)
        )
        
        if file_path:
            self.log_path_var.set(file_path)
    
    def _save_settings(self):
        """Save application settings"""
        # Update credentials
        self.credentials["username"] = self.username_var.get()
        self.credentials["password"] = self.password_var.get()
        self.credentials["enable_secret"] = self.enable_var.get()
        
        # Update log file
        self.log_file = self.log_path_var.get()
        
        # Save settings to file
        settings = {
            "credentials": self.credentials,
            "log_file": self.log_file,
            "log_enabled": self.log_enabled.get(),
            "timeout": self.timeout_var.get()
        }
        
        try:
            settings_file = os.path.join(os.path.expanduser("~"), "network_admin_settings.json")
            with open(settings_file, "w") as f:
                json.dump(settings, f)
                
            messagebox.showinfo("Settings Saved", "Settings saved successfully")
            
            # Update logging configuration
            logging.getLogger().handlers[0].close()
            logging.basicConfig(
                filename=self.log_file,
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
                force=True
            )
            
            # Log setting update
            if self.log_enabled.get():
                logging.info("Settings updated")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def _load_settings(self):
        """Load application settings"""
        settings_file = os.path.join(os.path.expanduser("~"), "network_admin_settings.json")
        
        if not os.path.exists(settings_file):
            return
        
        try:
            with open(settings_file, "r") as f:
                settings = json.load(f)
                
            # Update credentials
            if "credentials" in settings:
                self.credentials = settings["credentials"]
                self.username_var.set(self.credentials["username"])
                self.password_var.set(self.credentials["password"])
                self.enable_var.set(self.credentials["enable_secret"])
                
            # Update log file
            if "log_file" in settings:
                self.log_file = settings["log_file"]
                self.log_path_var.set(self.log_file)
                
            # Update log enabled
            if "log_enabled" in settings:
                self.log_enabled.set(settings["log_enabled"])
                
            # Update timeout
            if "timeout" in settings:
                self.timeout_var.set(settings["timeout"])
                
        except Exception as e:
            messagebox.showwarning("Warning", f"Failed to load settings: {str(e)}")
    
    def _reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all settings to defaults?"):
            # Reset credentials
            self.credentials = {"username": "", "password": "", "enable_secret": ""}
            self.username_var.set("")
            self.password_var.set("")
            self.enable_var.set("")
            
            # Reset log file
            self.log_file = os.path.join(os.path.expanduser("~"), "network_admin_logs.txt")
            self.log_path_var.set(self.log_file)
            
            # Reset other settings
            self.log_enabled.set(True)
            self.timeout_var.set(5)
            
            messagebox.showinfo("Reset Complete", "Settings have been reset to defaults")
            
            # Log reset
            if self.log_enabled.get():
                logging.info("Settings reset to defaults")


# Implement real device connection functions for production use

def connect_to_device(device):
    """Connect to a network device using Netmiko"""
    device_params = {
        'device_type': device['type'],
        'ip': device['ip'],
        'username': device['username'],
        'password': device['password'],
        'secret': device['enable_secret'],
        'timeout': 10,
    }
    
    try:
        connection = ConnectHandler(**device_params)
        if device['type'].startswith('cisco'):
            connection.enable()
        return connection
    except Exception as e:
        raise Exception(f"Failed to connect to device: {str(e)}")

def get_device_temperature(connection, device_type):
    """Get the temperature of a device based on its type"""
    commands = {
        'cisco_ios': 'show environment temperature',
        'cisco_nxos': 'show environment temperature',
        'juniper': 'show chassis environment',
        'alcatel_aos': 'show system temperature'
    }
    
    command = commands.get(device_type)
    if not command:
        raise Exception("Unsupported device type for temperature check")
    
    output = connection.send_command(command)
    
    # Different parsing for different device types
    if device_type.startswith('cisco'):
        # Parse Cisco output
        match = re.search(r'(\d+) Celsius', output)
        if match:
            temp = match.group(1)
            return {
                'temperature': f"{temp}°C",
                'status': 'Normal' if int(temp) < 60 else 'Warning',
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    elif device_type == 'juniper':
        # Parse Juniper output
        match = re.search(r'Temperature:\s+(\d+) degrees', output)
        if match:
            temp = match.group(1)
            return {
                'temperature': f"{temp}°C",
                'status': 'Normal' if int(temp) < 55 else 'Warning',
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    elif device_type == 'alcatel_aos':
        # Parse Alcatel output
        match = re.search(r'Chassis temperature:\s+(\d+)', output)
        if match:
            temp = match.group(1)
            return {
                'temperature': f"{temp}°C",
                'status': 'Normal' if int(temp) < 65 else 'Warning',
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    
    # Default return if parsing fails
    return {
        'temperature': 'Unknown',
        'status': 'Unknown',
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def find_disconnected_ports(connection, device_type):
    """Find disconnected ports on a device based on its type"""
    commands = {
        'cisco_ios': 'show interfaces status',
        'cisco_nxos': 'show interface status',
        'juniper': 'show interfaces terse',
        'alcatel_aos': 'show interfaces port status'
    }
    
    command = commands.get(device_type)
    if not command:
        raise Exception("Unsupported device type for port status check")
    
    output = connection.send_command(command)
    disconnected_ports = []
    
    # Different parsing for different device types
    if device_type.startswith('cisco'):
        # Parse Cisco output
        for line in output.splitlines():
            if 'disabled' in line.lower() or 'notconnect' in line.lower():
                match = re.search(r'^(\S+)', line)
                if match:
                    disconnected_ports.append(match.group(1))
    elif device_type == 'juniper':
        # Parse Juniper output
        for line in output.splitlines():
            if 'down' in line.lower():
                match = re.search(r'^(\S+)', line)
                if match:
                    disconnected_ports.append(match.group(1))
    elif device_type == 'alcatel_aos':
        # Parse Alcatel output
        for line in output.splitlines():
            if 'down' in line.lower():
                match = re.search(r'^(\S+)', line)
                if match:
                    disconnected_ports.append(match.group(1))
    
    return {
        'disconnected_ports': disconnected_ports,
        'total_ports': len(re.findall(r'^\S+', output, re.MULTILINE)),
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# Main application
def main():
    root = tk.Tk()
    app = NetworkAdminTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()