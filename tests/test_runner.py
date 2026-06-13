from gql_permission_mapper.runner import flatten_fields


def test_flatten_fields_handles_nested_lists() -> None:
    payload = {
        "listApiKeys": [
            {"id": "one", "owner": {"email": "a@example.test"}},
            {"id": "two", "owner": {"email": "b@example.test"}},
        ]
    }

    assert flatten_fields(payload) == {
        "listApiKeys",
        "listApiKeys.id",
        "listApiKeys.owner",
        "listApiKeys.owner.email",
    }

