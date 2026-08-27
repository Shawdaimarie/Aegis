from aegis.core.hashing import canonical_json, content_id


def test_content_id_is_order_independent():
    assert content_id({"a": 1, "b": 2}) == content_id({"b": 2, "a": 1})


def test_canonical_json_is_compact_and_sorted():
    assert canonical_json({"b": [1, 2], "a": "x"}) == '{"a":"x","b":[1,2]}'
