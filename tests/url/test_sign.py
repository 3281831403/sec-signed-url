"""15 个测试，覆盖 10 个缺陷与 5 条正常行为。测试不可修改。"""

import hmac

from engine.url import sign as sign_module
from engine.url.sign import (
    canonical_string,
    expiry_ok,
    ip_bind_ok,
    scope_ok,
    sign,
    url_batch,
    validate_policy,
    verify,
)

SECRET = "s3cr3t"
NOW = 1_000_000
POLICY = {
    "secret": SECRET,
    "max_ttl": 3600,
    "allowed_prefixes": ["/files"],
    "require_ip_binding": True,
    "signed_ip": "10.0.0.0/8",
}


def _request(method="GET", path="/files/a", expires=NOW + 600, extra=None, ip="10.1.2.3"):
    extra = {} if extra is None else dict(extra)
    canonical = canonical_string(method, path, expires, extra)
    return {
        "method": method,
        "path": path,
        "expires": expires,
        "extra": extra,
        "ip": ip,
        "signature": sign(SECRET, canonical),
    }


def test_canonical_ignores_insertion_order():
    first = canonical_string("GET", "/files/a", NOW + 600, {"b": "2", "a": "1"})
    second = canonical_string("GET", "/files/a", NOW + 600, {"a": "1", "b": "2"})
    assert first == second
    assert first == "expires=1000600&extra=a%3D1%26b%3D2&method=GET&path=%2Ffiles%2Fa"


def test_canonical_includes_method():
    assert canonical_string("GET", "/files/a", NOW, {}) != canonical_string(
        "POST", "/files/a", NOW, {}
    )


def test_canonical_includes_path():
    assert canonical_string("GET", "/files/a", NOW, {}) != canonical_string(
        "GET", "/files/b", NOW, {}
    )


def test_verify_uses_constant_time_compare(monkeypatch):
    canonical = canonical_string("GET", "/files/a", NOW, {})
    good = sign(SECRET, canonical)
    seen = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        seen.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(sign_module.hmac, "compare_digest", spy)
    assert verify(SECRET, canonical, good) is True
    assert seen, "verify 必须调用 hmac.compare_digest，不能用普通等号"
    bad = good[:-1] + ("0" if good[-1] != "0" else "1")
    assert verify(SECRET, canonical, bad) is False


def test_expiry_rejects_ttl_over_limit():
    assert expiry_ok(NOW, NOW, 3600) is True
    assert expiry_ok(NOW + 3600, NOW, 3600) is True
    assert expiry_ok(NOW + 3601, NOW, 3600) is False


def test_expiry_compares_timestamps_numerically():
    assert expiry_ok(1000, 999, 10) is True
    assert expiry_ok(999, 1000, 10) is False


def test_scope_respects_directory_boundary():
    assert scope_ok("/files/a", ["/files"]) is True
    assert scope_ok("/files", ["/files"]) is True
    assert scope_ok("/files2/a", ["/files"]) is False
    assert scope_ok("/files/a", ["/files/"]) is True


def test_ip_bind_supports_cidr():
    assert ip_bind_ok("10.0.0.0/8", "10.9.8.7") is True
    assert ip_bind_ok("10.0.0.0/8", "11.0.0.1") is False
    assert ip_bind_ok("192.168.1.5", "192.168.1.5") is True
    assert ip_bind_ok("192.168.1.5", "192.168.1.6") is False


def test_policy_reports_missing_ttl_limit():
    valid = {"max_ttl": 3600, "allowed_prefixes": ["/files"], "require_ip_binding": True}
    assert validate_policy(valid) == []
    assert validate_policy(dict(valid, max_ttl=86401)) == ["有效期超过上限或未设置"]
    assert validate_policy({"max_ttl": 3600, "allowed_prefixes": [], "require_ip_binding": True}) == [
        "未限制路径"
    ]
    assert validate_policy(
        {"max_ttl": 3600, "allowed_prefixes": ["/files"], "require_ip_binding": False}
    ) == ["未绑定地址"]


def test_batch_verifies_each_request_signature():
    first = _request(path="/files/a")
    second = dict(first, path="/files/b")
    assert url_batch([first, second], POLICY, NOW) == {0: True, 1: False}


def test_valid_signature_passes():
    canonical = canonical_string("GET", "/files/a", NOW + 600, {"op": "read"})
    signature = sign(SECRET, canonical)
    assert len(signature) == 64
    assert signature == signature.lower()
    assert verify(SECRET, canonical, signature) is True


def test_tampered_path_fails():
    signature = sign(SECRET, canonical_string("GET", "/files/a", NOW + 600, {}))
    tampered = canonical_string("GET", "/files/b", NOW + 600, {})
    assert verify(SECRET, tampered, signature) is False


def test_expired_link_rejected():
    assert expiry_ok(NOW - 1, NOW, 3600) is False
    assert expiry_ok(NOW, NOW, 3600) is True


def test_path_outside_prefix_rejected():
    assert scope_ok("/etc/passwd", ["/files", "/reports"]) is False


def test_two_batches_match_individual_checks():
    requests = [
        _request(),
        _request(path="/files/b", extra={"op": "read"}),
        _request(path="/etc/passwd"),
        _request(expires=NOW - 1),
    ]
    expected = {}
    for index, request in enumerate(requests):
        canonical = canonical_string(
            request["method"], request["path"], request["expires"], request["extra"]
        )
        expected[index] = (
            verify(SECRET, canonical, request["signature"])
            and expiry_ok(request["expires"], NOW, POLICY["max_ttl"])
            and scope_ok(request["path"], POLICY["allowed_prefixes"])
        )
    first = url_batch(requests, POLICY, NOW)
    second = url_batch(requests, POLICY, NOW)
    assert first == expected
    assert second == expected
    assert first == {0: True, 1: True, 2: False, 3: False}