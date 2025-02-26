Network Administrator Tool
A comprehensive network management application for IT administrators to monitor and manage network switches from different vendors including Cisco, Juniper, and Alcatel.
Features

Device Management

Add devices manually or import from Excel
Ping devices to check availability
Manage device credentials


Network Operations

Check switch operating temperatures
Find disconnected ports
Trace network loops
Scan VLANs
Check device information
View interface status


Logging

Automatic logging of all operations
Export logs for record keeping
User-configurable log settings



Installation
Prerequisites

Windows 10 or 11
Python 3.7 or higher (if running from source)

Option 1: Run the Executable

Download the NetworkAdminTool.exe file
Double-click to run the application

Option 2: Install from Source

Clone or download this repository
Install dependencies:
Copypip install -r requirements.txt

Run the application:
Copypython network_admin_tool.py


Building the Executable
To create your own executable:

Install PyInstaller:
Copypip install pyinstaller

Run the build script:
Copypython build.py

The executable will be created in the dist folder

Usage Guide
Adding Devices

Go to the "Devices" tab
Click "Add Device"
Enter the IP address and select device type
Provide credentials or use defaults
Click "Add"

Importing Devices from Excel

Create an Excel file with columns: "ip" and "type"
Go to the "Devices" tab
Click "Import from Excel"
Select your Excel file

Running Operations

Select a device from the list
Go to the "Operations" tab
Click on the desired operation button
View results in the right panel

Loop Tracing
The application can detect network loops by analyzing ping responses and patterns of packet loss:

Select a device
Click "Trace Loop" in the Operations tab
The application will analyze ping patterns to identify possible loops
If found, the loop path will be displayed

Temperature Monitoring
To check the operating temperature of switches:

Select a device
Click "Check Temperature" in the Operations tab
The temperature and status will be displayed

Finding Disconnected Ports

Select a device
Click "Find Disconnected Ports" in the Operations tab
View the list of ports that are not connected

Settings

Configure default credentials in the Settings tab
Set logging preferences
All settings are saved between sessions

Troubleshooting

Connection Errors: Verify IP address and credentials
Command Errors: Ensure device type is selected correctly
Excel Import Issues: Verify column names match the expected format

Log File
The application maintains a log file at:

Windows: C:\Users\<username>\network_admin_logs.txt

Security Note
This application stores credentials in a settings file. Ensure appropriate access controls are in place on the computer running this application.