import json

import httpx
import pytest

from app.services.ikuai_service import IkuaiService
from app.services.ikuai_v4_service import IkuaiV4Service, create_ikuai_service


@pytest.fixture
def router():
    records, writes = [], []
    state = {"fail_read": False, "fail_write": False, "page_size": 100}

    def handle(request):
        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.url.path.startswith(IkuaiV4Service.RULES)
        if request.method == "GET":
            if state["fail_read"]:
                return httpx.Response(200, json={"code": 3007})
            page = int(request.url.params.get("page", 1))
            start = (page - 1) * 100
            return httpx.Response(200, json={"code": 0, "results": {
                "data": records[start:start + 100], "total": len(records)}})
        writes.append(request.method)
        if state["fail_write"]:
            return httpx.Response(200, json={"code": 3001})
        if request.method == "POST":
            record = json.loads(request.content)
            record["id"] = len(records) + 1
            records.append(record)
        elif request.method == "PUT":
            record = next(r for r in records if str(r["id"]) == request.url.path.rsplit("/", 1)[1])
            record.update(json.loads(request.content))
        elif request.method == "DELETE":
            records[:] = [r for r in records if str(r["id"]) != request.url.path.rsplit("/", 1)[1]]
        return httpx.Response(200, json={"code": 0})

    service = IkuaiV4Service("https://router.test", "test-token")
    service.close()
    service._session = httpx.Client(transport=httpx.MockTransport(handle),
                                   base_url="https://router.test",
                                   headers={"Authorization": "Bearer test-token"})
    yield service, records, writes, state
    service.close()


def test_create_update_and_idempotent_sync(router):
    service, records, writes, _ = router
    hosts = [{"domain": "tracker.example.test", "ip": "192.0.2.1"}]
    assert service.sync_hosts_to_dns(hosts)
    assert records[0]["domain"] == "tracker.example.test"
    assert service.sync_hosts_to_dns(hosts)
    assert writes == ["POST"]
    hosts[0]["ip"] = "192.0.2.2"
    assert service.sync_hosts_to_dns(hosts)
    assert writes == ["POST", "PUT"]
    assert records[0]["id"] == 1


def test_all_pages_are_read(router):
    service, records, _, _ = router
    records.extend({"id": i} for i in range(205))
    assert len(service.get_dns_records()) == 205


def test_read_failure_aborts_without_writes(router):
    service, _, writes, state = router
    state["fail_read"] = True
    assert not service.sync_hosts_to_dns([{"domain": "a.test", "ip": "192.0.2.1"}])
    assert writes == []


def test_foreign_record_conflict_aborts_entire_plan(router):
    service, records, writes, _ = router
    records.append({"id": 1, "domain": "b.test", "comment": "manual"})
    assert not service.sync_hosts_to_dns([
        {"domain": "a.test", "ip": "192.0.2.1"}, {"domain": "b.test", "ip": "192.0.2.1"}])
    assert writes == []


def test_failed_write_is_not_reported_as_success(router):
    service, _, _, state = router
    state["fail_write"] = True
    assert not service.sync_hosts_to_dns([{"domain": "a.test", "ip": "192.0.2.1"}])
    assert not service.get_last_sync_status()


def test_ipv6_toggle_and_delete(router):
    service, records, _, _ = router
    assert service.sync_hosts_to_dns([{"domain": "a.test", "ip": "2001:db8::1"}])
    assert records[0]["parse_type"] == "ipv6"
    assert service.disable_dns_record(1)
    assert records[0]["enabled"] == "no"
    assert service.enable_dns_record(1)
    assert records[0]["enabled"] == "yes"
    assert service.delete_dns_record(1)
    assert records == []


def test_legacy_factory_and_https_requirement():
    legacy = create_ikuai_service(host="http://router.test", password="test")
    assert type(legacy) is IkuaiService
    legacy.close()
    with pytest.raises(ValueError):
        create_ikuai_service(host="http://router.test", api_version="v4", token="test")
