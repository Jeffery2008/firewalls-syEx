from setuptools import setup, find_packages
from pathlib import Path

# Read README.md for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Core dependencies
REQUIRED = [
    "google-generativeai>=0.3.0",
    "typing-extensions>=4.5.0",
    "pyyaml>=6.0",
    "z3-solver>=4.12.0",
    "jsonschema>=4.17.0",
]

# Optional dependencies
EXTRAS = {
    "dev": [
        "pytest>=7.3.1",
        "pytest-cov>=4.1.0",
        "mypy>=1.5.1",
        "black>=23.7.0",
        "pylint>=2.17.5",
        "pre-commit>=3.3.3",
    ],
    "docs": [
        "sphinx>=7.1.2",
        "sphinx-rtd-theme>=1.3.0",
    ],
}

setup(
    name="firewalls-syex",
    version="0.1.0",
    author="Jeffery",
    description="IPTables to eBPF Translation Tool with LLM Support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/firewalls-syex",
    packages=find_packages(exclude=["tests*", "examples*"]),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=REQUIRED,
    extras_require=EXTRAS,
    entry_points={
        "console_scripts": [
            "firewalls-syex=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="iptables, ebpf, firewall, llm, translation",
)
