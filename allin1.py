import os
import subprocess
import PyInstaller.__main__

# Define application metadata
APP_NAME = "NetworkAdminTool"
MAIN_PY = "network_admin_tool.py"  # Main script file name

# Step 1: Run setup.py to build the package
print("Running setup.py to create package...")
subprocess.run(["python", "setup.py", "sdist", "bdist_wheel"], check=True)

# Step 2: Run PyInstaller to generate the executable
print("Building executable with PyInstaller...")
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