"""签名下载链接的核心实现。

本模块共 8 个公开函数。测试位于 tests/url/test_sign.py，
不可修改；实现以各函数 docstring 的契约为准。
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import time
import urllib.parse

MAX_TTL = 86400

TTL_ISSUE = "有效期超过上限或未设置"
PATH_ISSUE = "未限制路径"
IP_ISSUE = "未绑定地址"


def canonical_string(method: str, path: str, expires: int, extra: dict[str, str]) -> str:
    """返回规范化签名串，字段顺序固定为 expires、extra、method、path。

    每个字段渲染为 key=value，字段之间用 & 连接。value 先做百分号编码：
    urllib.parse.quote(value, safe="")，字符集 UTF-8。extra 先按 key 升序
    拼成 k1=v1&k2=v2（此时不编码），再整体作为 extra 字段的值参与编码；
    extra 为空时该值为空字符串。因此字段的字典插入顺序不影响结果。

    示例：
        canonical_string("GET", "/files/a", 1000, {"b": "2", "a": "1"})
        返回 expires=1000&extra=a%3D1%26b%3D2&method=GET&path=%2Ffiles%2Fa
    """
    inner = "&".join(f"{key}={extra[key]}" for key in sorted(extra))
    fields = {
        "expires": str(expires),
        "extra": inner,
        "method": method,
        "path": path,
    }
    return "&".join(
        f"{key}={urllib.parse.quote(fields[key], safe='')}"
        for key in ("expires", "extra", "method", "path")
    )


def sign(secret: str, canonical: str) -> str:
    """用 HMAC-SHA256 对规范化串签名，返回小写十六进制字符串。

    secret 与 canonical 均按 UTF-8 编码；返回值固定为 64 个十六进制字符。
    """
    return hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify(secret: str, canonical: str, provided: str) -> bool:
    """恒定时间校验签名。

    必须使用 hmac.compare_digest 比较，禁止使用普通等号。provided 不是
    字符串时返回 False；签名正确返回 True，否则返回 False。
    """
    if not isinstance(provided, str):
        return False
    expected = sign(secret, canonical)
    return hmac.compare_digest(expected, provided)


def expiry_ok(expires: int, now: int, max_ttl: int) -> bool:
    """判断有效期窗口，满足 now <= expires <= now + max_ttl 时返回 True。

    两端均包含。expires、now、max_ttl 都是整数秒，禁止转成字符串比较。
    时钟容差为 0，即只接受上述闭区间内的链接，不做任何宽限。
    max_ttl 为负时返回 False。
    """
    if max_ttl < 0:
        return False
    return now <= expires <= now + max_ttl


def scope_ok(path: str, allowed_prefixes: list[str]) -> bool:
    """路径必须落在 allowed_prefixes 的某个前缀内，按目录边界匹配。

    前缀先去掉尾部斜杠；前缀 / 表示放行全部路径。path 等于前缀，或以
    “前缀 + /” 开头才算命中，例如 /reports2 不属于 /reports。
    allowed_prefixes 为空返回 False；不处理 . 与 .. 段。
    """
    for prefix in allowed_prefixes:
        prefix = prefix.rstrip("/")
        if prefix == "":
            return True
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def ip_bind_ok(signed_ip: str, request_ip: str) -> bool:
    """绑定地址校验，支持 IPv4 单地址与 IPv4 CIDR。

    signed_ip 可以是 10.1.2.3，也可以是 10.0.0.0/8 这样的网段；
    request_ip 是单个 IPv4 地址。命中返回 True；任一侧格式非法返回 False。
    仅支持 IPv4，不做 DNS 解析。
    """
    try:
        request = ipaddress.IPv4Address(request_ip)
        if "/" in signed_ip:
            network = ipaddress.IPv4Network(signed_ip, strict=False)
            return request in network
        return request == ipaddress.IPv4Address(signed_ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


def validate_policy(policy: dict) -> list[str]:
    """返回策略问题列表，顺序固定为有效期、路径、地址。

    policy 字段：max_ttl 为整数秒；allowed_prefixes 为前缀列表；
    require_ip_binding 为布尔值；signed_ip 供批量校验使用。
    max_ttl 必须是 1 到 86400 的整数（含两端），否则追加 TTL_ISSUE；
    allowed_prefixes 必须是非空列表，每项以 / 开头且不能等于 /，否则追加
    PATH_ISSUE；require_ip_binding 必须为 True，否则追加 IP_ISSUE。
    全部满足时返回空列表。
    """
    issues: list[str] = []
    max_ttl = policy.get("max_ttl")
    if (
        not isinstance(max_ttl, int)
        or isinstance(max_ttl, bool)
        or not 1 <= max_ttl <= MAX_TTL
    ):
        issues.append(TTL_ISSUE)
    prefixes = policy.get("allowed_prefixes")
    if (
        not isinstance(prefixes, list)
        or not prefixes
        or any(
            not isinstance(prefix, str) or not prefix.startswith("/") or prefix == "/"
            for prefix in prefixes
        )
    ):
        issues.append(PATH_ISSUE)
    if policy.get("require_ip_binding") is not True:
        issues.append(IP_ISSUE)
    return issues


def url_batch(requests: list[dict], policy: dict, now: int) -> dict[int, bool]:
    """批量校验，返回 索引 -> 是否通过 的字典。

    requests 中每项包含 method、path、expires、extra、signature、ip。
    对每个请求独立重算规范化串，再依次检查：策略问题为空、签名有效、
    expiry_ok、scope_ok；require_ip_binding 为 True 时还检查
    ip_bind_ok(policy["signed_ip"], request["ip"])。
    不得跨请求复用规范化串或签名结果。
    """
    results: dict[int, bool] = {}
    policy_ok = not validate_policy(policy)
    secret = policy.get("secret", "")
    for index, request in enumerate(requests):
        canonical = canonical_string(
            request["method"], request["path"], request["expires"], request["extra"]
        )
        ok = (
            policy_ok
            and verify(secret, canonical, request["signature"])
            and expiry_ok(request["expires"], now, policy["max_ttl"])
            and scope_ok(request["path"], policy["allowed_prefixes"])
        )
        if ok and policy.get("require_ip_binding") is True:
            ok = ip_bind_ok(policy["signed_ip"], request["ip"])
        results[index] = ok
    return results
