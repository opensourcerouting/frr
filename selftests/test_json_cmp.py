import pytest

from topotato.utils import JSONCompareDirective, JSONCompareDirectiveWrongSide, JSONCompareIgnoreContent, JSONCompareIgnoreExtraListitems, JSONCompareKeyShouldNotExist, JSONCompareListKeyedDict, JSONCompareUnexpectedDirective, json_cmp


@pytest.fixture
def bgp_json_output():
    return {
        "neighbors": {
            "192.0.2.1": {
                "state": "up",
                "as": 65001,
                "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
            },
            "192.0.2.2": {
                "state": "down",
                "as": 65002,
                "prefixes_received": [],
            },
        }
    }



# Test for missing keys
def test_missing_keys(bgp_json_output):
    expected_data = {
        "neighbors": {
            "192.0.2.1": {
                "state": "up",
                "as": 65001,
                "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
            },
            "192.0.2.2": {
                "state": "down",
                "as": 65002,
                "prefixes_received": [],
            },
            "192.0.2.3": {  # Missing key
                "state": "up",
                "as": 65003,
                "prefixes_received": ["30.0.0.0/24"],
            },
        }
    }
    assert json_cmp(bgp_json_output, expected_data) is not None

# Test for mismatched values
def test_mismatched_values(bgp_json_output):
    expected_data = {
        "neighbors": {
            "192.0.2.1": {
                "state": "up",
                "as": 65001,
                "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
            },
            "192.0.2.2": {
                "state": "down",
                "as": 65003,  # Mismatched value
                "prefixes_received": [],
            },
        }
    }
    assert json_cmp(bgp_json_output, expected_data) is not None
    
    
    import pytest

# Test for JSONCompareIgnoreContent class
def test_json_compare_ignore_content(bgp_json_output):
    expected_data = {
        "neighbors": {
            "192.0.2.1": JSONCompareIgnoreContent(),  # Ignoring content
            "192.0.2.2": {
                "state": "down",
                "as": 65002,
                "prefixes_received": [],
            },
        }
    }
    assert json_cmp(bgp_json_output, expected_data) is None

# Test for JSONCompareIgnoreExtraListitems class
def test_json_compare_ignore_extra_listitems(bgp_json_output):
    expected_data = {
        "neighbors": {
            "192.0.2.1": {
                "state": "up",
                "as": 65001,
                "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
            },
            "192.0.2.2": JSONCompareIgnoreExtraListitems(),  # Ignoring extra list items
        }
    }
    assert json_cmp(bgp_json_output, expected_data) is None


# Test for JSONCompareListKeyedDict class
def test_json_compare_list_keyed_dict(bgp_json_output):
    expected_data = {
        "neighbors": JSONCompareListKeyedDict(
            {
                "192.0.2.1": {
                    "state": "up",
                    "as": 65001,
                    "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
                }
            }
        )  # Compare as a list of dicts regardless of order
    }
    assert json_cmp(bgp_json_output, expected_data) is None

# Test for JSONCompareKeyShouldNotExist class
def test_json_compare_key_should_not_exist(bgp_json_output):
    expected_data = {
        "neighbors": {
            "192.0.2.1": {
                "state": "up",
                "as": 65001,
                "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
            },
            "192.0.2.2": {
                "state": "down",
                "as": 65002,
                "prefixes_received": [],
            },
            "192.0.2.3": JSONCompareKeyShouldNotExist(),  # Key should not exist
        }
    }
    assert json_cmp(bgp_json_output, expected_data) is None, "Key should not exist"
    
# WIP
# # Test for JSONCompareDirectiveWrongSide class
# def test_json_compare_directive_wrong_side(bgp_json_output):
#     class CustomDirective(JSONCompareDirective):
#         pass

#     actual_data = {
#         "neighbors": {
#             "192.0.2.1": {
#                 "state": "up",
#                 "as": 65001,
#                 "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
#             },
#             "192.0.2.2": {
#                 "state": "down",
#                 "as": 65002,
#                 "prefixes_received": [],
#             },
#             "192.0.2.3": CustomDirective(),  # Custom directive on the actual data side
#         }
#     }

#     expected_data = {
#         "neighbors": {
#             "192.0.2.1": {
#                 "state": "up",
#                 "as": 65001,
#                 "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
#             },
#             "192.0.2.2": {
#                 "state": "down",
#                 "as": 65002,
#                 "prefixes_received": [],
#             },
#         }
#     }

#     with pytest.raises(JSONCompareDirectiveWrongSide):
#         json_cmp(actual_data, expected_data)


# def test_json_compare_unexpected_directive(bgp_json_output):
#     class CustomDirective(JSONCompareDirective):
#         pass

#     expected_data = {
#         "neighbors": {
#             "192.0.2.1": {
#                 "state": "up",
#                 "as": 65001,
#                 "prefixes_received": ["10.0.0.0/24", "20.0.0.0/24"],
#             },
#             "192.0.2.2": {
#                 "state": "down",
#                 "as": 65002,
#                 "prefixes_received": [],
#             },
#             "192.0.2.3": CustomDirective(),  # Unexpected directive
#         }
#     }

#     with pytest.raises(JSONCompareUnexpectedDirective):
#         json_cmp(bgp_json_output, expected_data)