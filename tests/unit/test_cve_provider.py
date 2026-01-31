from vibescan.core.cve_provider import StubCVEProvider, top_n_cves

def test_stub_lookup():
    """Test standard lookup returns expected items."""
    provider = StubCVEProvider()
    cves = provider.lookup_by_fingerprint(["wordpress"])
    
    assert len(cves) >= 1
    assert any(c["cve_id"] == "CVE-2021-9999" for c in cves)

def test_stub_lookup_empty():
    """Test lookup with no matches."""
    provider = StubCVEProvider()
    cves = provider.lookup_by_fingerprint(["unknown_component"])
    assert len(cves) == 0

def test_top_n_cves_sorting():
    """Test that sorting prioritizes exploit_exists=True and then CVSS."""
    cves = [
        {"id": 1, "cvss": 5.0, "exploit_exists": False},
        {"id": 2, "cvss": 9.0, "exploit_exists": True},
        {"id": 3, "cvss": 10.0, "exploit_exists": False},
        {"id": 4, "cvss": 8.0, "exploit_exists": True},
    ]
    
    # Expected order:
    # 1. id 2 (exploit True, cvss 9.0)
    # 2. id 4 (exploit True, cvss 8.0)
    # 3. id 3 (exploit False, cvss 10.0)
    # 4. id 1 (exploit False, cvss 5.0)
    
    sorted_cves = top_n_cves(cves, n=4)
    assert len(sorted_cves) == 4
    assert sorted_cves[0]["id"] == 2
    assert sorted_cves[1]["id"] == 4
    assert sorted_cves[2]["id"] == 3
    assert sorted_cves[3]["id"] == 1

def test_top_n_cves_limit():
    """Test that result count is limited by n."""
    cves = [{"cvss": i} for i in range(10)]
    limited = top_n_cves(cves, n=3)
    assert len(limited) == 3
