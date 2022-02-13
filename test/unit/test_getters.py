"""Tests for getters."""
import functools
from itertools import zip_longest
import inspect
import json

import pytest
from napalm.base.test import helpers
from napalm.base.test import models
from napalm.base.test import conftest
from napalm.base.test.getters import BaseTestGetters


# from typing_extensions import TypedDict

# InterfaceDict = TypedDict(
#     "InterfaceDict",
#     {
#         "is_up": bool,
#         "is_enabled": bool,
#         "description": str,
#         "last_flapped": float,
#         "mtu": int,
#         "speed": float,
#         "mac_address": str,
#     },
# )

def list_dicts_diff(prv, nxt):
    """Compare two lists of dicts."""
    result = []
    for prv_element, nxt_element in zip_longest(prv, nxt, fillvalue={}):
        intermediate_result = dict_diff(prv_element, nxt_element)
        if intermediate_result:
            result.append(intermediate_result)
    return result


def dict_diff(prv, nxt):
    """Return a dict of keys that differ with another config object."""
    keys = set(list(prv.keys()) + list(nxt.keys()))
    result = {}

    for k in keys:
        if isinstance(prv.get(k), dict):
            if isinstance(nxt.get(k), dict):
                "If both are dicts we do a recursive call."
                diff = dict_diff(prv.get(k), nxt.get(k))
                if diff:
                    result[k] = diff
            else:
                "If only one is a dict they are clearly different"
                result[k] = {"result": prv.get(k), "expected": nxt.get(k)}
        else:
            "Ellipsis is a wildcard." ""
            if prv.get(k) != nxt.get(k) and nxt.get(k) != "...":
                result[k] = {"result": prv.get(k), "expected": nxt.get(k)}
    return result


def wrap_test_cases(func):
    """Wrap test cases."""
    func.__dict__["build_test_cases"] = True

    @functools.wraps(func)
    def mock_wrapper(cls, test_case):
        for patched_attr in cls.device.patched_attrs:
            attr = getattr(cls.device, patched_attr)
            attr.current_test = func.__name__
            attr.current_test_case = test_case

        try:
            # This is an ugly, ugly, ugly hack because some python objects don't load
            # as expected. For example, dicts where integers are strings
            result = json.loads(json.dumps(func(cls, test_case)))
        except IOError:
            if test_case == "no_test_case_found":
                pytest.fail("No test case for '{}' found".format(func.__name__))
            else:
                raise
        except NotImplementedError:
            pytest.skip("Method not implemented")
            return

        # This is an ugly, ugly, ugly hack because some python objects don't load
        # as expected. For example, dicts where integers are strings

        try:
            expected_result = attr.expected_result
        except IOError as e:
            raise Exception("{}. Actual result was: {}".format(e, json.dumps(result)))
        if isinstance(result, list):
            diff = list_dicts_diff(result, expected_result)
        else:
            diff = dict_diff(result, expected_result)
        if diff:
            print("Resulting JSON object was: {}".format(json.dumps(result)))
            raise AssertionError("Expected result varies on some keys {}".format(json.dumps(diff)))

        for patched_attr in cls.device.patched_attrs:
            attr = getattr(cls.device, patched_attr)
            attr.current_test = ""  # Empty them to avoid side effects
            attr.current_test_case = ""  # Empty them to avoid side effects

        return result

    @functools.wraps(func)
    def real_wrapper(cls, test_case):
        try:
            return func(cls, test_case)
        except NotImplementedError:
            pytest.skip("Method not implemented")
            return

    if conftest.NAPALM_TEST_MOCK:
        return mock_wrapper
    else:
        return real_wrapper


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    # @wrap_test_cases
    # def test_get_interfaces(self, test_case):
    #     """Test get_interfaces."""
    #     get_interfaces = self.device.get_interfaces()

    #     assert len(get_interfaces) > 0

    #     for interface, interface_data in get_interfaces.items():
    #         assert helpers.test_model(models.InterfaceDict, interface_data)
    #     # for interface, interface_data in get_interfaces.items():
    #     #     assert helpers.test_model(InterfaceDict, interface_data)

    #     return get_interfaces

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""
        get_interfaces = self.device.get_interfaces()
        if test_case in {"empty_interfaces",}:
            assert len(get_interfaces) == 0
        else:
            assert len(get_interfaces) > 0

            # for interface, interface_data in get_interfaces.items():
            #     assert helpers.test_model(InterfaceDict, interface_data)
        for interface, interface_data in get_interfaces.items():
            assert helpers.test_model(models.interface, interface_data)

        return get_interfaces
