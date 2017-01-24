#!/usr/bin/env python3

from setuptools import setup, find_packages, Extension
import os
import subprocess
import shutil

script_dir = os.path.dirname(os.path.realpath(__file__))
libnitro_source_path = os.path.join(script_dir, 'nitro', 'libnitro')
libnitro_build_path = os.path.join(script_dir, 'nitro', 'libnitro', 'build')
# mkdir build
os.makedirs(libnitro_build_path, exist_ok=True)
# cmake
p = subprocess.Popen('cmake {}'.format(libnitro_source_path), shell=True, cwd=libnitro_build_path)
p.wait()
# make
p = subprocess.Popen('make', shell=True, cwd=libnitro_build_path)
p.wait()



setup(
    name="nitro",
    version="0.0.1",
    author="F-Secure Corporation",
    author_email="mathieu.tarral@gmail.com",
    description=("""Hypervisor based tracing and monitoring prototype to trap
        guest syscalls and analyze them"""),
    packages=find_packages(),
    install_requires=[
        'Pebble',
    ],
    data_files=[('nitro/libnitro', ['nitro/libnitro/libnitro.so'])],
    keywords="nitro hyperisor monitoring tracing syscall",
)
