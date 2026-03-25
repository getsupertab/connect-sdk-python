from __future__ import annotations

import connect


def test_package_exports_only_client_credentials_surface() -> None:
    assert connect.__all__ == ["obtain_license_token", "SupertabConnectError"]
    assert hasattr(connect, "obtain_license_token")
    assert hasattr(connect, "SupertabConnectError")
