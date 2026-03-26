import connect


def test_package_exports_public_api() -> None:
    """All expected symbols are present in connect.__all__."""
    expected = {
        "EnforcementMode",
        "LicenseTokenInvalidReason",
        "LicenseTokenVerificationResult",
        "RSLVerificationResult",
        "SupertabConnectError",
        "obtain_license_token",
        "verify_license_token",
    }
    assert set(connect.__all__) == expected
