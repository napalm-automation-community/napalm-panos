# 0.6.1 - 2024-04

### Added
- #108 Added Support for sdwan interfaces
- #105 Include interface description for get_interfaces method


## Fixed
- #115 Update package dependencies, fix tests

# 0.6.0 - 2022-02

### Added
- #102 Added Support for get_arp_table method
- #99 Added documentation of supported getters
- #93 Added ability to lock config optionally
- #104 Added change log document

## Fixed
- #101 Handles unable to convert to int for edge case with interfaces
- #103 Fix Empty List of Interfaces

## 0.5.4 - 2022-02

### Fixed
- #94 load_replace_candidate broke

### Changed
- #96 Update Readme


## 0.5.3 - 2022-02

### Fixed
- #88 - Convert package, add linters, fix linting issues 
- #70 - Update lldp when single entry is shown
- #64 - Improve version handling for netmiko 
- #73 - update splitlines on string of config 
- #62 - Fix for the get_interfaces method called devices with sub-ifaces
- #90 - Update lxml for security reason 


## 0.5.2 - 2018-01

- Update get_interfaces
- Update get_interfaces_ip
- Fix PIP 10 


## 0.5.1 - 2018-01

- Fixes imports
- Long outstanding sync of master and devel


## 0.5.0 - 2018-01

- Updated to compatible with NAPALM 2.0


## 0.4.0 - 2017-02

- Bypass a couple of pylama errors: #36 
- Add support for get_route_to and get_lldp_neighbors: #34 
- Convert to use Tox: #33 


## 0.3.0 - 2016-12

- Added `is_alive` method.
- Added Python3 support.


## 0.2.2 - 2016-12

- #28 Migrate to new testing framework


## 0.2.1 - 2016-11

- #23 API key and SSH key support: https://github.com/napalm-automation/napalm-panos/pull/23
- Use napalm-base>=0.18.0


## 0.2.0 - 2016-10

- Updates to napalm core


## 0.1.0 - 2016-05

New panos driver.

Supported methods:
- http://napalm.readthedocs.io/en/latest/support/index.html#configuration-support-matrix
- http://napalm.readthedocs.io/en/latest/support/index.html#getters-support-matrix

- Caveats: http://napalm.readthedocs.io/en/latest/support/panos.html
