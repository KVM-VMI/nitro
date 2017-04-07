#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="nitro",
    version="0.0.1",
    author="F-Secure Corporation",
    author_email="mathieu.tarral@gmail.com",
    description=("""Hypervisor based tracing and monitoring prototype to trap
        guest syscalls and analyze them"""),
    packages=find_packages(),
    install_requires=[
        'docopt',
        'libvirt-python',
    ],
    keywords="nitro hyperisor monitoring tracing syscall",
)
