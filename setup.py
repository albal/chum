"""
Setup configuration for the Chum certificate lifecycle management tool.
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="chum",
    version="0.1.0",
    description="Certificate lifecycle management – deploy wildcard certs to HP printers, Proxmox, OpenShift, Dell iDRAC",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/albal/chum",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
    ],
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0",
        "requests>=2.31",
    ],
    extras_require={
        "acme": ["acme>=2.6", "josepy>=1.14"],
        "k8s": ["kubernetes>=28.1"],
        "yaml": ["PyYAML>=6.0"],
        "all": ["acme>=2.6", "josepy>=1.14", "kubernetes>=28.1", "PyYAML>=6.0"],
    },
    entry_points={
        "console_scripts": [
            "chum=chum.cli:main",
        ],
    },
)
