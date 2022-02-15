[![PyPI](https://img.shields.io/pypi/v/napalm-panos.svg)](https://pypi.python.org/pypi/napalm-panos)
[![PyPI](https://img.shields.io/pypi/dm/napalm-panos.svg)](https://pypi.python.org/pypi/napalm-panos)
[![Build Status](https://travis-ci.org/napalm-automation/napalm-panos.svg?branch=master)](https://travis-ci.org/napalm-automation/napalm-panos)
[![Coverage Status](https://coveralls.io/repos/github/napalm-automation/napalm-panos/badge.svg?branch=develop)](https://coveralls.io/github/napalm-automation/napalm-panos?branch=develop)

# NAPALM PANOS

This is community version of [NAPALM](https://napalm.readthedocs.io/) for the Palo Alto firewall operating system. For standard tutorials and overview of NAPALM, please review their documentation.

# Configuration Support

This table identifies the currently available configuration methods supported:

| Feature                   | Supported |
| ------------------------- | --------- |
| Config Replace            | ✅        |
| Commit Confirm            | ❌        |
| Config Merge              | ✅        |
| Compare Config            | ✅        |
| Atomic Changes            | ✅        |
| Rollback                  | ✅        |

> Commit Confirm is not supported by the vendor at the time of this writing.

Configuration Lock is also supported, but the `optional_args` `config_lock` key set to `True`. You can see in this example.

```python
from napalm import get_network_driver

panos_device = "device"
panos_user = "admin"
panos_password = "pass123"
driver = get_network_driver("panos")
optional_args = {"config_lock": True}

with driver(panos_device, panos_user, panos_password, optional_args=optional_args) as device:
    device.load_replace_candidate(filename="2022-01-01-intended-config.xml")
    device.commit_config()

```

As shown in the example above, the use of NAPALM's context manager is supported and recommended to use. 

The locks are acquired and released using XML API. Locks for config and commit lock are obtained and released separately from each other. Both locks are
released automatically by the device when a commit is made on the device.

For troubleshooting:
- The code crashed in a way that the lock could not be removed?
    - Remove the lock manually (CLI, API, Web UI). The lock can only be removed by the administrator who set it, or by a superuser.
- The lock disappeared in the middle of program execution?
    - Did someone do a commit on the device? The locks are removed automatically when the administrator who set the locks performs a commit operation on the device.

# Supported Getters

This table identifies the currently available getters and the support for each:

| Getter                    | Supported |
| ------------------------- | --------- |
| get_arp_table             | ✅        |
| get_bgp_config            | ❌        |
| get_bgp_neighbors         | ❌        |
| get_bgp_neighbors_detail  | ❌        |
| get_config                | ✅        |
| get_environment           | ❌        |
| get_facts                 | ✅        |
| get_firewall_policies     | ❌        |
| get_interfaces            | ✅        |
| get_interfaces_counters   | ❌        |
| get_interfaces_ip         | ✅        |
| get_ipv6_neighbors_table  | ❌        |
| get_lldp_neighbors        | ✅        |
| get_lldp_neighbors_detail | ❌        |
| get_mac_address_table     | ❌        |
| get_network_instances     | ❌        |
| get_ntp_peers             | ❌        |
| get_ntp_servers           | ❌        |
| get_ntp_stats             | ❌        |
| get_optics                | ❌        |
| get_probes_config         | ❌        |
| get_probes_results        | ❌        |
| get_route_to              | ✅        |
| get_snmp_information      | ❌        |
| get_users                 | ❌        |
| get_vlans                 | ❌        |
| is_alive                  | ✅        |
| ping                      | ❌        |
| traceroute                | ❌        |
