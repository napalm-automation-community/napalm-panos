"""Tests for getters."""

from napalm.base.test import helpers
from napalm.base.test import models
from napalm.base.test.getters import BaseTestGetters
from napalm.base.test.getters import wrap_test_cases

import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""
        get_interfaces = self.device.get_interfaces()
        if test_case in {
            "empty_interfaces",
        }:
            assert len(get_interfaces) == 0
        else:
            assert len(get_interfaces) > 0

            # for interface, interface_data in get_interfaces.items():
            #     assert helpers.test_model(InterfaceDict, interface_data)
        for interface, interface_data in get_interfaces.items():
            assert helpers.test_model(models.interface, interface_data)

        return get_interfaces
