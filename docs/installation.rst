Installation Guide
=================

This guide will help you set up the IPTables to eBPF Translation Tool on your system.

System Requirements
-----------------

Before installing, ensure your system meets these requirements:

* Python 3.8 or higher
* Linux kernel 5.5 or higher (for eBPF support)
* Clang and LLVM toolchain
* libbpf development headers

Dependencies Installation
-----------------------

Ubuntu/Debian
^^^^^^^^^^^^

.. code-block:: bash

   sudo apt-get update
   sudo apt-get install -y clang llvm libbpf-dev python3-dev

RHEL/CentOS
^^^^^^^^^^^

.. code-block:: bash

   sudo dnf install clang llvm libbpf-devel python3-devel

Package Installation
------------------

From PyPI
^^^^^^^^^

The recommended way to install is via pip:

.. code-block:: bash

   pip install firewalls-syex

From Source
^^^^^^^^^^

For the latest development version:

.. code-block:: bash

   git clone https://github.com/yourusername/firewalls-syex.git
   cd firewalls-syex
   pip install -e .[dev]

The ``[dev]`` option installs additional dependencies for development.

API Key Setup
------------

The tool requires a Google Gemini API key for operation:

1. Obtain an API key from the `Google AI Studio <https://makersuite.google.com/app/apikey>`_
2. Set up the key:

   .. code-block:: bash

      python -m firewalls_syex setup --api-key YOUR_API_KEY

Verification
-----------

Verify the installation:

.. code-block:: bash

   python -m firewalls_syex --version
   python -m firewalls_syex verify-setup

Troubleshooting
--------------

Common Issues
^^^^^^^^^^^^

1. Missing libbpf:
   
   .. code-block:: bash

      sudo apt-get install libbpf-dev  # Ubuntu/Debian
      sudo dnf install libbpf-devel    # RHEL/CentOS

2. Python.h not found:
   
   .. code-block:: bash

      sudo apt-get install python3-dev  # Ubuntu/Debian
      sudo dnf install python3-devel    # RHEL/CentOS

3. Clang/LLVM tools not found:
   
   .. code-block:: bash

      sudo apt-get install clang llvm   # Ubuntu/Debian
      sudo dnf install clang llvm       # RHEL/CentOS

Getting Help
-----------

If you encounter any issues:

1. Check the :doc:`troubleshooting` guide
2. Search existing `GitHub Issues <https://github.com/yourusername/firewalls-syex/issues>`_
3. Open a new issue with detailed information about your problem

Next Steps
----------

* Read the :doc:`quickstart` guide
* Try the :doc:`examples`
* Configure your :doc:`settings`
