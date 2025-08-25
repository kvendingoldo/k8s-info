import pytest
from k8s_info.utils import parse_memory_k8s


def test_parse_memory_k8s():
    assert parse_memory_k8s("1024Ki") == 1
    assert parse_memory_k8s("1Mi") == 1
    assert parse_memory_k8s("1Gi") == 1024
    assert parse_memory_k8s("1048576") == 1
    assert parse_memory_k8s("bad") == 0


def test_import_cli():
    import k8s_info.cli
