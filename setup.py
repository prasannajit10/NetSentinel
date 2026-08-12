from setuptools import setup, find_packages

setup(
    name="netsentinel",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "jinja2>=3.1.0",
        "rich>=13.0.0",
        "pytest>=7.0.0",
    ],
    entry_points={
        "console_scripts": [
            "netsentinel=netsentinel.main:main",
        ],
    },
    python_requires=">=3.8",
    author="J Prasannajit",
    description="Network anomaly detection and DFIR report generator",
)
