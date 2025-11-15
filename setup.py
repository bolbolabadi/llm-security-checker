#!/usr/bin/env python3
"""
Setup script for LLM Security Checker
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="llm-security-checker",
    version="1.0.0",
    author="bolbolsec",
    description="Comprehensive Security Assessment Tool for LLM Endpoints",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bolbolsec/llm-security-checker",
    py_modules=[
        "llm_security_checker",
        "llm_attacks",
        "scan_state",
        "curl_parser"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "llm-security-checker=llm_security_checker:main",
        ],
    },
)
