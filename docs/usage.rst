Usage Guide
===========

This guide explains how to use the IPTables to eBPF Translation Tool effectively.

Command Line Interface
--------------------

Basic Commands
^^^^^^^^^^^^

1. Translate IPTables rules to eBPF:

   .. code-block:: bash

      python -m firewalls_syex translate input_rules.txt

2. Validate rule syntax:

   .. code-block:: bash

      python -m firewalls_syex validate input_rules.txt

3. Check translation correctness:

   .. code-block:: bash

      python -m firewalls_syex verify translated_rules.c

Command Options
^^^^^^^^^^^^^

Common options for all commands:

* ``--output-dir PATH``: Specify output directory
* ``--verbose``: Enable detailed logging
* ``--debug``: Enable debug mode
* ``--config PATH``: Use custom configuration file

Graphical Interface
------------------

Starting the GUI
^^^^^^^^^^^^^^

Launch the graphical interface:

.. code-block:: bash

   python -m firewalls_syex gui

GUI Features
^^^^^^^^^^

1. Rule Management:
   * Import/export rules
   * Edit rules with syntax highlighting
   * Rule validation

2. Translation:
   * Interactive translation
   * Progress monitoring
   * Error highlighting

3. Verification:
   * Automated correctness checks
   * Visual diff comparison
   * Error reporting

Configuration
------------

Settings File
^^^^^^^^^^^

The tool uses a JSON configuration file:

.. code-block:: json

   {
     "api_key": "YOUR_API_KEY",
     "output_dir": "~/firewalls-output",
     "template_dir": "~/firewalls-templates",
     "log_level": "INFO"
   }

Environment Variables
^^^^^^^^^^^^^^^^^^

Configure using environment variables:

.. code-block:: bash

   export FIREWALLS_API_KEY="your-api-key"
   export FIREWALLS_OUTPUT_DIR="~/output"
   export FIREWALLS_LOG_LEVEL="DEBUG"

Rule Syntax
----------

Basic Structure
^^^^^^^^^^^^^

Rules follow IPTables syntax:

.. code-block:: text

   iptables -A CHAIN -p PROTOCOL -s SOURCE -d DEST -j ACTION

Example Rules
^^^^^^^^^^^

1. Basic TCP rule:

   .. code-block:: text

      iptables -A INPUT -p tcp --dport 80 -j ACCEPT

2. Complex rule with multiple conditions:

   .. code-block:: text

      iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.0.0.0/8 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

Best Practices
------------

Performance
^^^^^^^^^^

1. Order rules by frequency:
   * Put most-used rules first
   * Group similar rules together

2. Use appropriate chains:
   * INPUT for incoming traffic
   * OUTPUT for outgoing traffic
   * FORWARD for routed traffic

3. Optimize rule conditions:
   * Use network ranges when possible
   * Combine similar rules
   * Remove redundant rules

Troubleshooting
-------------

Common Issues
^^^^^^^^^^^

1. Translation fails:
   * Check rule syntax
   * Verify API key
   * Check network connection

2. Verification errors:
   * Compare input/output
   * Check rule compatibility
   * Verify eBPF constraints

Next Steps
---------

* View :doc:`examples` for more complex scenarios
* Learn about :doc:`templates` for custom rules
* Read :doc:`architecture` for technical details
