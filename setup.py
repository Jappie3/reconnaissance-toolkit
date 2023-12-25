from setuptools import setup

setup(
    name="reconnaissance-toolkit",
    version="0.0.1",
    entry_points={
        "console_scripts": [
            "reconnaissance-toolkit = reconnaissance_toolkit.main:main",
        ],
    },
    install_requires=[
        "requests",
        "dnspython",
        "scapy",
        "python-nmap",
        "validators",
        "types-ipaddress",
        "pygments",
    ],
)
