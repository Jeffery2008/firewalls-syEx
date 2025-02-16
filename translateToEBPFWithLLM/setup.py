from setuptools import setup, find_packages
from pathlib import Path

# Read requirements.txt
requirements = Path('requirements.txt').read_text().splitlines()
requirements = [r for r in requirements if not r.startswith('#') and r.strip()]

# Read long description from README
long_description = Path('README.md').read_text()

setup(
    name="translateToEBPFWithLLM",
    version="0.1.0",
    author="Jeffery",
    description="A tool to translate iptables rules to eBPF using LLM",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/translateToEBPFWithLLM",
    packages=find_packages(exclude=["tests*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'iptables2ebpf=translateToEBPFWithLLM.main:main',
            'iptables2ebpf-gui=translateToEBPFWithLLM.gui:main',
        ],
    },
    package_data={
        'translateToEBPFWithLLM': [
            'schema.json',
            'templates/*.c',
            'templates/*.h',
        ],
    },
    include_package_data=True,
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.3.0',
            'mypy>=1.5.0',
        ],
    }
)
