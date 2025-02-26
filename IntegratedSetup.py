from setuptools import setup, find_packages
import PyInstaller.__main__
import os
import sys

# Define a custom command for building the executable
from setuptools.command.build_py import build_py

class BuildExe(build_py):
    description = "Build an executable using PyInstaller"
    
    def run(self):
        # Run the standard build_py first
        build_py.run(self)
        
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
            '--icon=%s' % os.path.join('D://PingMyNetwork', 'icon.ico'),
            '--clean',
            '--noupx',
        ])
        
        print(f"Build completed. Executable created at: dist/{APP_NAME}.exe")

# Setup configuration
setup(
    name="NetworkAdminTool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pandas",
        "openpyxl",
        "paramiko",
        "netmiko",
        "pyinstaller",  # Added PyInstaller as a dependency
    ],
    entry_points={
        "console_scripts": [
            "networkadmintool=networktool.main:main",
        ],
    },
    author="Glenn Dbritto",
    author_email="glenndbritto101@gmail.com",
    description="Network Administration Tool for IT Administrators",
    keywords="network, administration, cisco, juniper, alcatel",
    python_requires=">=3.7",
    cmdclass={
        'build_exe': BuildExe,  # Register our custom command
    },
)