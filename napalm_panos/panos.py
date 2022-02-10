"""Napalm-panos."""
# pylint: disable=abstract-method,raise-missing-from
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

# std libs
import json
import os.path
import re
import time
import xml.etree
from datetime import datetime

from napalm.base import NetworkDriver
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.helpers import mac as standardize_mac
from napalm.base.utils.string_parsers import convert_uptime_string_seconds

from netmiko import ConnectHandler
from netmiko import __version__ as netmiko_version

import pan.xapi

from pkg_resources import parse_version

import requests

import requests_toolbelt

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

import xmltodict


# local modules


class PANOSDriver(NetworkDriver):  # pylint: disable=too-many-instance-attributes
    """PANOS Driver, that inhertis from the base napalm class."""

    def __init__(
        self, hostname, username, password, timeout=60, optional_args=None
    ):  # pylint: disable=too-many-arguments,super-init-not-called
        """Initialize the methods."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.loaded = False
        self.changed = False
        self.device = None
        self.ssh_device = None
        self.ssh_connection = False
        self.merge_config = False
        self.backup_file = None
        self.platform = "panos"

        if optional_args is None:
            optional_args = {}
        self.verify = optional_args.get("ssl_verify", False)

        netmiko_argument_map = {
            "port": None,
            "verbose": False,
            "use_keys": False,
            "key_file": None,
            "ssh_strict": False,
            "system_host_keys": False,
            "alt_host_keys": False,
            "alt_key_file": "",
            "ssh_config_file": None,
        }

        if parse_version(netmiko_version) >= parse_version("2.0.0"):
            netmiko_argument_map["allow_agent"] = False
        elif parse_version(netmiko_version) >= parse_version("1.1.0"):
            netmiko_argument_map["allow_agent"] = False

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for key in netmiko_argument_map.keys():
            try:
                self.netmiko_optional_args[key] = optional_args[key]
            except KeyError:
                pass
        self.api_key = optional_args.get("api_key", "")

    def open(self):
        """PANOS version of `open` method, see NAPALM for documentation."""
        try:
            if self.api_key:
                self.device = pan.xapi.PanXapi(hostname=self.hostname, api_key=self.api_key)
            else:
                self.device = pan.xapi.PanXapi(
                    hostname=self.hostname,
                    api_username=self.username,
                    api_password=self.password,
                )
        except ConnectionException as exc:
            raise ConnectionException(str(exc))

    def _open_ssh(self):
        try:
            self.ssh_device = ConnectHandler(
                device_type="paloalto_panos",
                ip=self.hostname,
                username=self.username,
                password=self.password,
                **self.netmiko_optional_args,
            )
        except ConnectionException as exc:
            raise ConnectionException(str(exc))

        self.ssh_connection = True

    def close(self):
        """PANOS version of `close` method, see NAPALM for documentation."""
        self.device = None
        if self.ssh_connection:
            self.ssh_device.disconnect()
            self.ssh_connection = False
            self.ssh_device = None

    def _import_file(self, filename):
        if not self.api_key:
            key = self.device.keygen()
        else:
            key = self.api_key

        params = {"type": "import", "category": "configuration", "key": key}

        path = os.path.basename(filename)

        # TODO: Disabling pylint consider-using-with is not correct, need to figure out proper solution
        mef = requests_toolbelt.MultipartEncoder(
            fields={
                "file": (path, open(filename, "rb"), "application/octet-stream")  # pylint: disable=consider-using-with
            }
        )

        if not self.verify:
            disable_warnings(InsecureRequestWarning)
        url = f"https://{self.hostname}/api/"
        request = requests.post(
            url,
            verify=self.verify,
            params=params,
            headers={"Content-Type": mef.content_type},
            data=mef,
        )

        # if something goes wrong just raise an exception
        request.raise_for_status()
        response = xml.etree.ElementTree.fromstring(request.content)  # nosec

        if response.attrib["status"] == "error":
            return False
        return path

    def is_alive(self):
        """PANOS version of `is_alive` method, see NAPALM for documentation."""
        if self.device:
            if self.ssh_connection:
                is_alive = self.ssh_device.remote_conn.transport.is_active()
            else:
                is_alive = True
        else:
            is_alive = False
        return {"is_alive": is_alive}

    def load_replace_candidate(self, filename=None, config=None):
        """PANOS version of `load_replace_candidate` method, see NAPALM for documentation."""
        if config:
            raise ReplaceConfigException("This method requires a config file.")

        if filename:
            if self.loaded is False:
                if self._save_backup() is False:
                    raise ReplaceConfigException("Error while storing backup config")

            path = self._import_file(filename)
            if path is False:
                msg = "Error while trying to move the config file to the device."
                raise ReplaceConfigException(msg)

            # Let's load the config.
            cmd = f"<load><config><from>{path}</from></config></load>"
            self.device.op(cmd=cmd)

            if self.device.status == "success":
                self.loaded = True
            raise ReplaceConfigException(f"Error while loading config from {path}")

        raise ReplaceConfigException("This method requires a config file.")

    def _get_file_content(self, filename):  # pylint: disable=no-self-use
        """Convenience method to get file content."""
        try:
            with open(filename, "r", encoding="utf-8") as file:
                content = file.read()
        except IOError:
            raise MergeConfigException(f"Error while opening {filename}. Make sure " "filename is correct.")
        return content

    def _send_merge_commands(self, config, file_config):
        """Netmiko is being used to push set commands."""
        if self.loaded is False:
            if self._save_backup() is False:
                raise MergeConfigException("Error while storing backup " "config.")
        if self.ssh_connection is False:
            self._open_ssh()

        if isinstance(config, str):
            if file_config:
                config = config.splitlines()
            else:
                config = str(config).splitlines()

        self.ssh_device.send_config_set(config)
        self.loaded = True
        self.merge_config = True

    def _get_candidate(self):
        """Convenience method to get candidate config."""
        candidate_command = "<show><config><candidate></candidate></config></show>"
        self.device.op(cmd=candidate_command)
        candidate = str(self.device.xml_root())
        return candidate

    def _get_running(self):
        """Convenience method to get running config."""
        self.device.show()
        running = str(self.device.xml_root())
        return running

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """Full and Sanitized is not supported, need to apply to pass tests. It is not clear to me if this construct exists in panos."""
        if full:
            raise NotImplementedError("Full config is not implemented for this platform")
        if sanitized:
            raise NotImplementedError("Sanitized is not implemented for this platform")
        configs = {}
        running = ""
        candidate = ""
        startup = ""

        if retrieve == "all":
            running = self._get_running()
            candidate = self._get_candidate()
        elif retrieve == "running":
            running = self._get_running()
        elif retrieve == "candidate":
            candidate = self._get_candidate()

        configs["running"] = running
        configs["candidate"] = candidate
        configs["startup"] = startup

        return configs

    def load_merge_candidate(self, filename=None, config=None):
        """PANOS version of `load_merge_candidate` method, see NAPALM for documentation."""
        if filename:
            file_config = True
            content = self._get_file_content(filename)
            config = content.splitlines()
            self._send_merge_commands(config, file_config)

        elif config:
            file_config = False
            self._send_merge_commands(config, file_config)

        else:
            raise MergeConfigException("You must provide either a file " "or a set-format string")

    def compare_config(self):
        """Netmiko is being used to obtain config diffs because pan-python doesn't support the needed command."""
        if self.ssh_connection is False:
            self._open_ssh()

        self.ssh_device.exit_config_mode()
        diff = self.ssh_device.send_command("show config diff")
        return diff.strip()

    def _save_backup(self):
        """Convenience method to save backup."""
        date_str = str(datetime.now().date()).replace(" ", "_")
        self.backup_file = f"config_{date_str}.xml"
        backup_command = f"<save><config><to>{self.backup_file}</to></config></save>"

        self.device.op(cmd=backup_command)
        if self.device.status == "success":
            return True
        return False

    def commit_config(self, message="", revert_in=None):
        """Netmiko is being used to commit the configuration because it takes a better care of results compared to pan-python."""
        if self.loaded:
            if self.ssh_connection is False:
                self._open_ssh()
            try:
                self.ssh_device.commit(comment=message)
                time.sleep(3)
                self.loaded = False
                self.changed = True
            except:  # noqa
                if self.merge_config:
                    raise MergeConfigException("Error while commiting config")
                raise ReplaceConfigException("Error while commiting config")
        raise ReplaceConfigException("No config loaded.")

    def discard_config(self):
        """PANOS version of `discard_config` method, see NAPALM for documentation."""
        if self.loaded:
            discard_cmd = f"<load><config><from>{self.backup_file}</from></config></load>"
            self.device.op(cmd=discard_cmd)

            if self.device.status == "success":
                self.loaded = False
                self.merge_config = False
            else:
                raise ReplaceConfigException("Error while loading backup config.")

    def rollback(self):
        """Netmiko is being used to commit the rollback configuration because it takes a better care of results compared to pan-python."""
        if self.changed:
            rollback_cmd = f"<load><config><from>{self.backup_file}</from></config></load>"
            self.device.op(cmd=rollback_cmd)
            time.sleep(5)

            if self.ssh_connection is False:
                self._open_ssh()
            try:
                self.ssh_device.commit()
                self.loaded = False
                self.changed = False
                self.merge_config = False
            except Exception:  # noqa pylint: disable=broad-except
                ReplaceConfigException("Error while loading backup config")

    def _extract_interface_list(self):
        self.device.op(cmd="<show><interface>all</interface></show>")
        interfaces_xml = xmltodict.parse(self.device.xml_root())
        interfaces_json = json.dumps(interfaces_xml["response"]["result"])
        interfaces = json.loads(interfaces_json)

        interface_set = set()

        for entry in interfaces.values():
            for entry_contents in entry.values():
                if isinstance(entry_contents, dict):
                    # If only 1 interface is listed, xmltodict returns a dictionary, otherwise
                    # it returns a list of dictionaries.
                    entry_contents = [entry_contents]
                for intf in entry_contents:
                    interface_set.add(intf["name"])

        return list(interface_set)

    def get_facts(self):
        """PANOS version of `get_facts` method, see NAPALM for documentation."""
        facts = {}

        try:
            self.device.op(cmd="<show><system><info></info></system></show>")
            system_info_xml = xmltodict.parse(self.device.xml_root())
            system_info_json = json.dumps(system_info_xml["response"]["result"]["system"])
            system_info = json.loads(system_info_json)
        except AttributeError:
            system_info = {}

        if system_info:
            facts["hostname"] = system_info["hostname"]
            facts["vendor"] = "Palo Alto Networks"
            facts["uptime"] = int(convert_uptime_string_seconds(system_info["uptime"]))
            facts["os_version"] = system_info["sw-version"]
            facts["serial_number"] = system_info["serial"]
            facts["model"] = system_info["model"]
            facts["fqdn"] = "N/A"
            facts["interface_list"] = self._extract_interface_list()

            facts["interface_list"].sort()

        return facts

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        neighbors = {}

        cmd = "<show><lldp><neighbors>all</neighbors></lldp></show>"
        try:
            self.device.op(cmd=cmd)
            lldp_table_xml = xmltodict.parse(self.device.xml_root())
            lldp_table_json = json.dumps(lldp_table_xml["response"]["result"]["entry"])
            lldp_table = json.loads(lldp_table_json)
        except AttributeError:
            lldp_table = []

        if isinstance(lldp_table, dict):
            # If only 1 interface is listed, xmltodict returns a dictionary, otherwise
            # it returns a list of dictionaries.
            lldp_table = [lldp_table]

        for lldp_item in lldp_table:

            local_int = lldp_item["@name"]

            if local_int not in neighbors.keys():
                neighbors[local_int] = []
            try:
                lldp_neighs = lldp_item.get("neighbors").get("entry")
            except AttributeError:
                lldp_neighs = ""
            if isinstance(lldp_neighs, dict):
                lldp_neighs = [lldp_neighs]

            for lldp_neighbor in lldp_neighs:
                neighbor = {}
                neighbor["hostname"] = lldp_neighbor["system-name"]
                neighbor["port"] = lldp_neighbor["port-id"]
                neighbors[local_int].append(neighbor)
        return neighbors

    def get_route_to(
        self, destination="", protocol="", longer=False
    ):  # pylint: disable=too-many-branches, too-many-statements
        """Return route details to a specific destination, learned from a certain protocol."""
        if longer:
            raise NotImplementedError("Longer is not implemented for this platform")

        # Note, it should be possible to query the FIB:
        # "<show><routing><fib></fib></routing></show>"
        # To add informations to this getter
        routes = {}

        if destination:
            destination = f"<destination>{destination}</destination>"
        if protocol:
            protocol = f"<type>{protocol}</type>"

        cmd = f"<show><routing><route>{protocol}{destination}</route></routing></show>"
        try:
            self.device.op(cmd=cmd)
            routes_table_xml = xmltodict.parse(self.device.xml_root())
            routes_table_json = json.dumps(routes_table_xml["response"]["result"]["entry"])
            routes_table = json.loads(routes_table_json)
        except (AttributeError, KeyError):
            routes_table = []

        if isinstance(routes_table, dict):
            routes_table = [routes_table]

        for route in routes_table:
            data = {
                "current_active": False,
                "last_active": False,
                "age": -1,
                "next_hop": "",
                "protocol": "",
                "outgoing_interface": "",
                "preference": -1,
                "inactive_reason": "",
                "routing_table": "default",
                "selected_next_hop": False,
                "protocol_attributes": {},
            }
            destination = route["destination"]
            flags = route["flags"]

            if "A" in flags:
                data["current_active"] = True
            else:
                data["current_active"] = False
            if "C" in flags:
                data["protocol"] = "connect"
            if "S" in flags:
                data["protocol"] = "static"
            if "R" in flags:
                data["protocol"] = "rip"
            if "R" in flags:
                data["protocol"] = "rip"
            if "O" in flags:
                data["protocol"] = "ospf"
            if "B" in flags:
                data["protocol"] = "bgp"
            if "H" in flags:
                data["protocol"] = "host"
            if route["age"] is not None:
                data["age"] = int(route["age"])
            if route["nexthop"] is not None:
                data["next_hop"] = route["nexthop"]
            if route["interface"] is not None:
                data["outgoing_interface"] = route["interface"]
            if route["metric"] is not None:
                data["preference"] = int(route["metric"])
            if route["virtual-router"] is not None:
                data["routing_table"] = route["virtual-router"]

            if destination not in routes.keys():
                routes[destination] = []
            routes[destination].append(data)

        return routes

    def get_interfaces(self):
        """PANOS version of `get_interfaces` method, see NAPALM for documentation."""
        subif_defaults = {
            "is_up": True,
            "is_enabled": True,
            "speed": 0,
            "last_flapped": -1.0,
            "mac_address": "",
            "mtu": 0,
            "description": "",
        }
        interface_pattern = re.compile(r"(ethernet\d+/\d+\.\d+)|(ae\d+\.\d+)|(loopback\.)|(tunnel\.)|(vlan\.)")
        interface_dict = {}
        interface_descr = {}
        interface_list = self._extract_interface_list()

        self.device.get(xpath="/config/devices/entry[@name='localhost.localdomain']/network/interface")
        for eth_int in self.device.element_result.findall(".//ethernet/entry"):
            name = eth_int.attrib["name"]
            description = eth_int.findtext(".//comment") or ''
            interface_descr[name] = description.strip()
        for eth_int in self.device.element_result.findall(".//vlan/units/entry"):
            name = eth_int.attrib["name"]
            description = eth_int.findtext(".//comment") or ''
            interface_descr[name] = description.strip()
        for eth_int in self.device.element_result.findall(".//tunnel/units/entry"):
            name = eth_int.attrib["name"]
            description = eth_int.findtext(".//comment") or ''
            interface_descr[name] = description.strip()
        interface_descr["loopback"] = self.device.element_result.findtext(".//loopback/comment") or ''

        for intf in interface_list:
            interface = {}
            cmd = f"<show><interface>{intf}</interface></show>"

            try:
                self.device.op(cmd=cmd)
                interface_info_xml = xmltodict.parse(self.device.xml_root())
                interface_info_json = json.dumps(interface_info_xml["response"]["result"]["hw"])
                interface_info = json.loads(interface_info_json)
            except KeyError as err:
                if intf.startswith(("loopback.", "tunnel.")) and 'hw' in str(err):
                    # loopback sub-ifs don't return a 'hw' key
                    interface_dict[intf] = subif_defaults
                    continue
                raise

            interface["is_up"] = interface_info.get("state") == "up"

            conf_state = interface_info.get("state_c")
            if conf_state == "down":
                interface["is_enabled"] = False
            elif conf_state in ("up", "auto"):
                interface["is_enabled"] = True
            else:
                msg = f"Unknown configured state {conf_state} for interface {intf}"
                raise RuntimeError(msg)

            interface["last_flapped"] = -1.0
            interface["mtu"] = 0
            interface["speed"] = interface_info.get("speed")
            # Loopback and down interfaces
            if interface["speed"] in ("[n/a]", "unknown"):
                interface["speed"] = 0
            else:
                interface["speed"] = int(interface["speed"])
            interface["mac_address"] = standardize_mac(interface_info.get("mac"))
            interface["description"] = interface_descr.get(intf, "")
            interface_dict[intf] = interface

        return interface_dict

    def get_interfaces_ip(self):
        """Return IP interface data."""

        def extract_ip_info(parsed_intf_dict):
            """Extract the IP Info from interfaces.

            IPv4
              - Primary IP is in the '<ip>' tag. If no v4 is configured the return value is 'N/A'.
              - Secondary IP's are in '<addr>'. If no secondaries, this field is not returned by
                the xmltodict.parse() method.
            IPv6
              - All addresses are returned in '<addr6>'. If no v6 configured, this is not returned
                either by xmltodict.parse().

            Args:
                parsed_intf_dict (dict): A dictionary in the format from xml to dict conversion from Palo API.

            Returns:
                list: Provides list of dictionary with informatoin per interface.
            """
            # Example of XML response for an intf with multiple IPv4 and IPv6 addresses:

            # <response status="success">
            #   <result>
            #     <ifnet>
            #       <entry>
            #         <name>ethernet1/5</name>
            #         <zone/>
            #         <fwd>N/A</fwd>
            #         <vsys>1</vsys>
            #         <dyn-addr/>
            #         <addr6>
            #           <member>fe80::d61d:71ff:fed8:fe14/64</member>
            #           <member>2001::1234/120</member>
            #         </addr6>
            #         <tag>0</tag>
            #         <ip>169.254.0.1/30</ip>
            #         <id>20</id>
            #         <addr>
            #           <member>1.1.1.1/28</member>
            #         </addr>
            #       </entry>
            #       {...}
            #     </ifnet>
            #     <hw>
            #       {...}
            #     </hw>
            #   </result>
            # </response>
            intf = parsed_intf_dict["name"]
            _ip_info = {intf: {}}

            v4_ip = parsed_intf_dict.get("ip")
            secondary_v4_ip = parsed_intf_dict.get("addr")
            v6_ip = parsed_intf_dict.get("addr6")

            if v4_ip != "N/A":
                address, pref = v4_ip.split("/")
                _ip_info[intf].setdefault("ipv4", {})[address] = {"prefix_length": int(pref)}

            if secondary_v4_ip is not None:
                members = secondary_v4_ip["member"]
                if not isinstance(members, list):
                    # If only 1 secondary IP is present, xmltodict converts field to a string, else
                    # it converts it to a list of strings.
                    members = [members]
                for address in members:
                    address, pref = address.split("/")
                    _ip_info[intf].setdefault("ipv4", {})[address] = {"prefix_length": int(pref)}

            if v6_ip is not None:
                members = v6_ip["member"]
                if not isinstance(members, list):
                    # Same "1 vs many -> string vs list of strings" comment.
                    members = [members]
                for address in members:
                    address, pref = address.split("/")
                    _ip_info[intf].setdefault("ipv6", {})[address] = {"prefix_length": int(pref)}

            # Reset dictionary if no addresses were found.
            if _ip_info == {intf: {}}:
                _ip_info = {}

            return _ip_info

        ip_interfaces = {}
        cmd = "<show><interface>all</interface></show>"

        self.device.op(cmd=cmd)
        interface_info_xml = xmltodict.parse(self.device.xml_root())
        interface_info_json = json.dumps(interface_info_xml["response"]["result"]["ifnet"]["entry"])
        interface_info = json.loads(interface_info_json)

        if isinstance(interface_info, dict):
            # Same "1 vs many -> dict vs list of dicts" comment.
            interface_info = [interface_info]

        for interface_dict in interface_info:
            ip_info = extract_ip_info(interface_dict)
            if ip_info:
                ip_interfaces.update(ip_info)

        return ip_interfaces
