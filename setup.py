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
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["nitro/build_libvmi.py:ffibuilder"],
    install_requires=[
        'cffi>=1.0.0',
        'docopt',
        'libvirt-python',
    ],
    keywords="nitro hyperisor monitoring tracing syscall",
)
