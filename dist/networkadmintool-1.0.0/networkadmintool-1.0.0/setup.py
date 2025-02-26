from setuptools import setup, find_packages

setup(
    name="NetworkAdminTool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pandas",
        "openpyxl",
        "paramiko",
        "netmiko",
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
)