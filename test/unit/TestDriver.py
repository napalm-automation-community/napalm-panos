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

"""Tests."""
import unittest

from napalm.base.test.base import TestConfigNetworkDriver

from napalm_panos import panos


class TestConfigDriver(unittest.TestCase, TestConfigNetworkDriver):
    """Group of tests that test Configuration related methods."""

    @classmethod
    def setUpClass(cls):
        """Test Driver.* methods."""
        hostname = "1.2.3.4"
        username = "test"
        password = "test"  # nosec
        cls.vendor = "panos"

        cls.device = panos.PANOSDriver(hostname, username, password, timeout=60)
        cls.device.open()

        cls.device.load_replace_candidate(filename="%s/initial.conf" % cls.vendor)
        cls.device.commit_config()
