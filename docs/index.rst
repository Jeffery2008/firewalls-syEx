IPTables to eBPF Translation Tool
================================

A comprehensive system for translating IPTables rules to eBPF using LLM technology, with built-in verification and validation.

Features
--------

- Translate IPTables rules to eBPF using Google's Gemini API
- Verify translation correctness using SMT formulas
- GUI interface for interactive management
- Command-line interface for automation
- Rule validation and syntax checking
- Performance analysis and optimization
- Support for complex firewall configurations

Getting Started
--------------

Installation
^^^^^^^^^^^

Install from PyPI:

.. code-block:: bash

   pip install firewalls-syex

Or install from source:

.. code-block:: bash

   git clone https://github.com/yourusername/firewalls-syex.git
   cd firewalls-syex
   pip install -e .

Configuration
^^^^^^^^^^^^

Set up your API key:

.. code-block:: bash

   python main.py setup --api-key YOUR_GEMINI_API_KEY

Usage
-----

GUI Interface
^^^^^^^^^^^^

Launch the graphical interface:

.. code-block:: bash

   python main.py gui

Command Line
^^^^^^^^^^^

Translate rules:

.. code-block:: bash

   python main.py translate examples/simple_rules.txt

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   usage
   examples
   configuration

.. toctree::
   :maxdepth: 2
   :caption: Developer Guide

   architecture
   contributing
   api_reference

.. toctree::
   :maxdepth: 1
   :caption: Reference

   rules_syntax
   templates
   command_reference

.. toctree::
   :maxdepth: 1
   :caption: Project Info

   changelog
   license

Indices and tables
-----------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
