#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="nitro",
    version="0.0.1",
    author="F-Secure Corporation",
    author_email="mathieu.tarral@gmail.com",
    description="Hypervisor based tracing and monitoring prototype to trap guest syscalls and analyze them",
    url="https://github.com/KVM-VMI/nitro",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "nitro = main:main"
        ]
    },
    install_requires=[
        'docopt',
        'libvirt-python',
        'ioctl_opt',
        'psutil'
    ],
    extras_require={
        "docs": ["sphinx", "sphinx_rtd_theme"],
        "tests": ["nose2"]
    },
    keywords=["nitro", "hyperisor", "monitoring", "tracing", "syscall"]
)
