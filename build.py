import PyInstaller.__main__
import os

# Define application metadata
APP_NAME = "NetworkAdminTool"
MAIN_PY = "network_admin_tool.py"  # Main script file name

# Generate the executable
PyInstaller.__main__.run([
    MAIN_PY,
    '--name=%s' % APP_NAME,
    '--onefile',
    '--windowed',
    '--add-data=%s' % os.path.join('resources', '*:resources'),
    '--icon=%s' % os.path.join('D:\PingMyNetwork', 'icon.ico'),
    '--clean',
    '--noupx',
])

print(f"Build completed. Executable created at: dist/{APP_NAME}.exe")