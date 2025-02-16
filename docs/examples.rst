Examples
========

This section provides practical examples of using the IPTables to eBPF Translation Tool in different scenarios.

Basic Examples
------------

Simple Web Server Rules
^^^^^^^^^^^^^^^^^^^^^

These rules allow HTTP and HTTPS traffic while blocking everything else:

.. code-block:: text

   # Allow established connections
   iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   
   # Allow SSH access
   iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   
   # Allow HTTP traffic
   iptables -A INPUT -p tcp --dport 80 -j ACCEPT
   
   # Allow HTTPS traffic
   iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   
   # Drop all other traffic
   iptables -A INPUT -j DROP

To translate these rules:

.. code-block:: bash

   python -m firewalls_syex translate webserver_rules.txt

Home Network Protection
^^^^^^^^^^^^^^^^^^^^

Protect your home network with these basic rules:

.. code-block:: text

   # Allow established connections
   iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   
   # Allow traffic from local network
   iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
   
   # Drop invalid packets
   iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
   
   # ICMP (ping) rate limiting
   iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
   iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
   
   # Drop all other incoming traffic
   iptables -A INPUT -j DROP

Intermediate Examples
------------------

Load Balancer Configuration
^^^^^^^^^^^^^^^^^^^^^^^^

Rules for a simple load balancer:

.. code-block:: text

   # Forward HTTP traffic to backend servers
   iptables -A PREROUTING -t nat -p tcp --dport 80 -m statistic --mode nth --every 3 --packet 0 -j DNAT --to-destination 10.0.1.101:80
   iptables -A PREROUTING -t nat -p tcp --dport 80 -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 10.0.1.102:80
   iptables -A PREROUTING -t nat -p tcp --dport 80 -j DNAT --to-destination 10.0.1.103:80
   
   # Enable masquerading for outgoing packets
   iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o eth0 -j MASQUERADE

To translate with verification:

.. code-block:: bash

   python -m firewalls_syex translate loadbalancer_rules.txt --verify

Network Segmentation
^^^^^^^^^^^^^^^^^

Segmenting internal networks:

.. code-block:: text

   # Allow traffic between DMZ and external network
   iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 80 -j ACCEPT
   iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 443 -j ACCEPT
   
   # Allow traffic from internal network to DMZ
   iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT
   
   # Block DMZ access to internal network
   iptables -A FORWARD -i eth1 -o eth2 -j DROP
   
   # Allow established connections
   iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   
   # Default: drop all other forwarded traffic
   iptables -A FORWARD -j DROP

Advanced Examples
--------------

Rate Limiting and DoS Protection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Protect against DoS attacks:

.. code-block:: text

   # Limit new TCP connections to 60 per minute
   iptables -A INPUT -p tcp --syn -m limit --limit 60/m --limit-burst 120 -j ACCEPT
   iptables -A INPUT -p tcp --syn -j DROP
   
   # Limit ICMP ping requests
   iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
   iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
   
   # Protect against port scanning
   iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
   iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP

Application-Layer Filtering
^^^^^^^^^^^^^^^^^^^^^^^^

Using string matching for application-layer filtering:

.. code-block:: text

   # Block SQL injection attempts
   iptables -A INPUT -p tcp --dport 80 -m string --string "UNION SELECT" --algo bm -j DROP
   iptables -A INPUT -p tcp --dport 80 -m string --string "1=1" --algo bm -j DROP
   
   # Block specific User-Agent
   iptables -A INPUT -p tcp --dport 80 -m string --string "malicious-bot" --algo bm -j DROP
   
   # Allow normal traffic
   iptables -A INPUT -p tcp --dport 80 -j ACCEPT

Command Reference
--------------

Translation with Debug Output
^^^^^^^^^^^^^^^^^^^^^^^^^^

Get detailed information during translation:

.. code-block:: bash

   python -m firewalls_syex translate rules.txt --debug

Using Custom Templates
^^^^^^^^^^^^^^^^^^^

Apply custom eBPF templates:

.. code-block:: bash

   python -m firewalls_syex translate rules.txt --template-dir ~/custom_templates

Validation Only
^^^^^^^^^^^^

Validate rules without translation:

.. code-block:: bash

   python -m firewalls_syex validate rules.txt

Debugging and Troubleshooting
---------------------------

Diagnosing Parse Errors
^^^^^^^^^^^^^^^^^^^

If rule parsing fails:

1. Run in debug mode:
   
   .. code-block:: bash
      
      python -m firewalls_syex validate rules.txt --debug
   
2. Check the specific error in the log:
   
   .. code-block:: bash
      
      tail -n 50 firewalls_syex.log

3. Fix the syntax and try again

Handling Unsupported Rules
^^^^^^^^^^^^^^^^^^^^^^^

When you encounter unsupported rules:

1. Check if the rule uses unsupported modules
2. Try to rewrite using supported syntax
3. Consider using custom templates for special cases:
   
   .. code-block:: bash
      
      python -m firewalls_syex translate rules.txt --template-dir ~/custom_templates

Performance Tips
-------------

Optimizing Large Rulesets
^^^^^^^^^^^^^^^^^^^^^

For large rulesets:

1. Group similar rules
2. Use the batch mode:
   
   .. code-block:: bash
      
      python -m firewalls_syex translate rules.txt --batch-size 10
   
3. Monitor memory usage with the `--stats` option

Real-World Scenarios
-----------------

Container Security Policy
^^^^^^^^^^^^^^^^^^^^^

Protecting container environments:

.. code-block:: text

   # Allow established connections
   iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   
   # Allow traffic to specific container network
   iptables -A FORWARD -d 172.17.0.0/16 -i eth0 -j ACCEPT
   
   # Allow container-to-container communication
   iptables -A FORWARD -s 172.17.0.0/16 -d 172.17.0.0/16 -j ACCEPT
   
   # Allow DNS queries
   iptables -A FORWARD -p udp --dport 53 -j ACCEPT
   iptables -A FORWARD -p tcp --dport 53 -j ACCEPT
   
   # Default policy
   iptables -A FORWARD -j DROP

Microservices Architecture
^^^^^^^^^^^^^^^^^^^^^^

Rules for a microservices environment:

.. code-block:: text

   # Internal API gateway (port 8080)
   iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 8080 -j ACCEPT
   
   # Service mesh communication (port 9000-9050)
   iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 9000:9050 -j ACCEPT
   
   # Metrics collection (port 9090)
   iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 9090 -j ACCEPT
   
   # Drop all other internal traffic
   iptables -A INPUT -s 10.0.0.0/8 -j DROP
   
   # Allow public endpoints
   iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   
   # Default policy
   iptables -A INPUT -j DROP
