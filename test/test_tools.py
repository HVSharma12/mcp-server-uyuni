import pytest
import respx
import httpx
from httpx import Response
import os
import sys
import json
from unittest.mock import MagicMock, AsyncMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")
os.environ.setdefault("UYUNI_USER", "mock-user")
os.environ.setdefault("UYUNI_PASS", "mock-pass")
os.environ.setdefault("UYUNI_MCP_WRITE_TOOLS_ENABLED", "true")
os.environ.setdefault("UYUNI_MCP_SSL_VERIFY", "false")

from mcp_server_uyuni import server
from mcp_server_uyuni.errors import HTTPError, AuthError, NotFoundError, UnexpectedResponse

@pytest.fixture
def mock_ctx():
    """Fixture for the MCP context."""
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.report_progress = AsyncMock()
    ctx.get_state.return_value = "mock_token"
    ctx.session.check_client_capability.return_value = False
    return ctx

@pytest.fixture
def mock_uyuni(respx_mock):
    """Fixture to mock Uyuni API calls using respx."""
    base_url = server.CONFIG["UYUNI_SERVER"]

    respx_mock.post(f"{base_url}/rhn/manager/api/oidcLogin").mock(
        return_value=Response(200, json={"success": True, "message": "Logged in"})
    )

    return respx_mock

@pytest.mark.asyncio
async def test_list_systems(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_data = [
        {"id": 1001, "name": "system1.example.com", "last_boot": "2023-01-01"},
        {"id": 1002, "name": "system2.example.com", "last_boot": "2023-01-02"},
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_systems("mock_token")

    assert len(result) == 2
    assert result[0]['system_name'] == "system1.example.com"
    assert result[0]['system_id'] == "1001"
    assert route.called

@pytest.mark.asyncio
async def test_get_system_details(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_details = {
        "id": 1001,
        "profile_name": "system1.example.com",
        "last_boot": "2023-10-27 10:00:00",
    }
    mock_uuid = "550e8400-e29b-41d4-a716-446655440000"
    mock_cpu = {
        "id": 1001,
        "family": "6",
        "model": "Intel Xeon",
        "vendor": "GenuineIntel",
        "mhz": "2500.000",
        "arch": "x86_64"
    }
    mock_network = {
        "id": 1001,
        "hostname": "system1.example.com",
        "ip": "192.168.1.10",
        "ip6": "fe80::1"
    }
    mock_products = [
        {"friendlyName": "SLES 15 SP4", "isBaseProduct": True}
    ]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getDetails").mock(return_value=Response(200, json={"success": True, "result": mock_details}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUuid").mock(return_value=Response(200, json={"success": True, "result": mock_uuid}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getCpu").mock(return_value=Response(200, json={"success": True, "result": mock_cpu}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getNetwork").mock(return_value=Response(200, json={"success": True, "result": mock_network}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getInstalledProducts").mock(return_value=Response(200, json={"success": True, "result": mock_products}))

    result = await server._get_system_details(system_id, mock_ctx, "mock_token")

    assert result['system_name'] == "system1.example.com"
    assert result['cpu']['model'] == "Intel Xeon"
    assert result['network']['ip'] == "192.168.1.10"
    assert result['installed_products'] == ["SLES 15 SP4"]

@pytest.mark.asyncio
async def test_add_system(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY", "secret_key")
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY_PASS", "passphrase")

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    route_bootstrap = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/bootstrapWithPrivateSshKey").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._add_system(
        host="new-system",
        token="mock_token",
        activation_key="1-KEY",
        ctx=mock_ctx,
    )
    assert "successfully scheduled" in result
    assert route_bootstrap.called

    payload = json.loads(route_bootstrap.calls.last.request.content)
    assert payload['host'] == "new-system"
    assert payload['activationKey'] == "1-KEY"
    assert payload['sshPrivKey'] == "secret_key"
    assert payload['sshPrivKeyPass'] == "passphrase"

@pytest.mark.asyncio
async def test_get_system_updates(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {"id": 501, "advisory_name": "SUSE-RU-2023:1234", "advisory_type": "Security Advisory", "advisory_synopsis": "Fixes stuff"}
    ]
    mock_unscheduled = []
    mock_cves = ["CVE-2023-0001"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(return_value=Response(200, json={"success": True, "result": mock_relevant}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(return_value=Response(200, json={"success": True, "result": mock_unscheduled}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(return_value=Response(200, json={"success": True, "result": mock_cves}))

    result = await server._get_system_updates(system_id, "mock_token", mock_ctx)

    assert result['has_pending_updates'] is True
    assert result['update_count'] == 1
    assert result['updates'][0]['advisory_name'] == "SUSE-RU-2023:1234"
    assert result['updates'][0]['cves'] == []
    assert result['meta']['include_cves'] is False


@pytest.mark.asyncio
async def test_get_system_updates_with_cves_and_pagination(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {"id": 501, "advisory_name": "ADV-1", "advisory_type": "Security", "advisory_synopsis": "Fix 1"},
        {"id": 502, "advisory_name": "ADV-2", "advisory_type": "Bugfix", "advisory_synopsis": "Fix 2"},
    ]
    mock_unscheduled = []
    mock_cves = ["CVE-2023-0001"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(return_value=Response(200, json={"success": True, "result": mock_relevant}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(return_value=Response(200, json={"success": True, "result": mock_unscheduled}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(return_value=Response(200, json={"success": True, "result": mock_cves}))

    result = await server._get_system_updates(system_id, "mock_token", mock_ctx, include_cves=True, limit=1, offset=0)

    assert result['meta']['include_cves'] is True
    assert result['meta']['returned_count'] == 1
    assert result['meta']['truncated'] is True
    assert result['updates'][0]['cves'] == ["CVE-2023-0001"]


@pytest.mark.asyncio
async def test_get_system_updates_tool_compact_default(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {
            "id": 501,
            "advisory_name": "ADV-1",
            "advisory_type": "Security",
            "advisory_synopsis": "Fix 1",
            "extra_field": "should_not_be_in_compact",
        }
    ]
    mock_unscheduled = []

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(return_value=Response(200, json={"success": True, "result": mock_relevant}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(return_value=Response(200, json={"success": True, "result": mock_unscheduled}))

    result = await server._get_system_updates(
        system_identifier=system_id,
        token="mock_token",
        ctx=mock_ctx,
        include_cves=False,
        limit=None,
        offset=0,
        compact_updates=True,
    )

    assert result['meta']['include_cves'] is False
    assert result['update_count'] == 1
    assert 'cves' not in result['updates'][0]
    assert 'extra_field' not in result['updates'][0]
    assert result['updates'][0]['update_id'] == 501


@pytest.mark.parametrize(
    "limit,offset,expected_limit,expected_offset",
    [
        (None, -5, None, 0),
        (0, -1, 0, 0),
        (-3, 2, 0, 2),
        (999, 0, 200, 0),
    ],
)
def test_normalize_pagination_edge_cases(limit, offset, expected_limit, expected_offset):
    normalized_limit, normalized_offset = server.normalize_pagination(limit=limit, offset=offset)
    assert normalized_limit == expected_limit
    assert normalized_offset == expected_offset


def test_client_supports_elicitation(mock_ctx):
    mock_ctx.session.check_client_capability.return_value = True
    assert server.client_supports_elicitation(mock_ctx) is True


@pytest.mark.asyncio
async def test_elicit_approval_skips_when_capability_missing(mock_ctx):
    mock_ctx.session.check_client_capability.return_value = False
    mock_ctx.elicit = AsyncMock()

    result = await server.elicit_approval(mock_ctx, "prompt")

    assert result is True
    mock_ctx.elicit.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("approve_value,expected", [(True, True), (False, False)])
async def test_elicit_approval_accept_result(mock_ctx, approve_value, expected):
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock(
        return_value=MagicMock(action="accept", data={"approve": approve_value})
    )

    result = await server.elicit_approval(mock_ctx, "prompt")

    assert result is expected


@pytest.mark.asyncio
async def test_elicit_approval_decline_result(mock_ctx):
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock(return_value=MagicMock(action="decline", data={"approve": True}))

    result = await server.elicit_approval(mock_ctx, "prompt")

    assert result is False


@pytest.mark.asyncio
async def test_get_system_updates_type_filter_and_counts(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {
            "id": 501,
            "advisory_name": "ADV-SEC",
            "advisory_type": "Security Advisory",
            "advisory_synopsis": "Security fix",
        },
        {
            "id": 502,
            "advisory_name": "ADV-BUG",
            "advisory_type": "Bug Fix Advisory",
            "advisory_synopsis": "Bug fix",
        },
    ]
    mock_unscheduled = [
        {"advisory_name": "ADV-SEC"}
    ]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_relevant})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_unscheduled})
    )

    result = await server._get_system_updates(
        system_identifier=system_id,
        token="mock_token",
        ctx=mock_ctx,
        include_cves=False,
        advisory_types=["security advisory"],
    )

    assert result["update_count"] == 1
    assert result["pending_update_count"] == 1
    assert result["queued_update_count"] == 0
    assert result["updates"][0]["advisory_name"] == "ADV-SEC"
    assert result["updates"][0]["application_status"] == "Pending"

@pytest.mark.asyncio
async def test_get_system_event_history(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001
    limit = 10
    offset = 0

    mock_data = [
        {"summary":"Hardware List Refresh scheduled by (system)","details":"","completed":"2026-01-10T04:00:07Z"}
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getEventHistory").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._get_system_event_history(system_id, limit, offset, None, mock_ctx, "mock_token")

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]['summary'] == "Hardware List Refresh scheduled by (system)"

    assert route.called
    assert route.calls.last.request.url.params['sid'] == str(system_id)

@pytest.mark.asyncio
async def test_schedule_specific_update(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001
    errata_id = 501

    route = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/scheduleApplyErrata").mock(
        return_value=Response(200, json={"success": True, "result": [12345]})
    )

    result = await server._schedule_specific_update(system_id, errata_id, mock_ctx, "mock_token")
    assert "successfully scheduled" in result
    assert f"{base_url}/rhn/schedule/ActionDetails.do?aid=12345" in result
    assert route.called

    payload = json.loads(route.calls.last.request.content)
    assert payload['sid'] == system_id
    assert payload['errataIds'] == [errata_id]
    assert payload['allowModules'] is True

@pytest.mark.asyncio
async def test_schedule_pending_updates_to_system(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {"id": 501, "advisory_name": "SUSE-RU-2023:1234", "advisory_type": "Security Advisory", "advisory_synopsis": "Fixes stuff"}
    ]
    mock_unscheduled = []
    mock_cves = ["CVE-2023-0001"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(return_value=Response(200, json={"success": True, "result": mock_relevant}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(return_value=Response(200, json={"success": True, "result": mock_unscheduled}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(return_value=Response(200, json={"success": True, "result": mock_cves}))

    route_schedule = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/scheduleApplyErrata").mock(
        return_value=Response(200, json={"success": True, "result": [12345]})
    )

    result = await server._schedule_pending_updates_to_system(system_id, "mock_token", mock_ctx)
    assert "successfully scheduled" in result
    assert f"{base_url}/rhn/schedule/ActionDetails.do?aid=12345" in result
    assert route_schedule.called

    payload = json.loads(route_schedule.calls.last.request.content)
    assert payload['sid'] == system_id
    assert payload['errataIds'] == [501]
    assert payload['allowModules'] is True

@pytest.mark.asyncio
async def test_remove_system(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1001, "name": "sys1"}]})
    )

    route_delete = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/deleteSystem").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._remove_system(system_id, mock_ctx, "mock_token")
    assert "successfully removed" in result
    assert route_delete.called

@pytest.mark.asyncio
async def test_schedule_system_reboot(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    route_reboot = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/scheduleReboot").mock(
        return_value=Response(200, json={"success": True, "result": 12346})
    )

    result = await server._schedule_system_reboot(system_id, "mock_token", mock_ctx)
    assert "successfully scheduled" in result
    assert f"{base_url}/rhn/schedule/ActionDetails.do?aid=12346" in result
    assert route_reboot.called

@pytest.mark.asyncio
async def test_cancel_action(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    action_id = 12345

    route = mock_uyuni.post(f"{base_url}/rhn/manager/api/schedule/cancelActions").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._cancel_action(action_id, "mock_token", mock_ctx)
    assert "Successfully canceled action" in result
    assert route.called

@pytest.mark.asyncio
async def test_create_system_group(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "new-group"
    description = "description"

    route_create = mock_uyuni.post(f"{base_url}/rhn/manager/api/systemgroup/create").mock(
        return_value=Response(200, json={"success": True, "result": {"id": 101, "name": group_name}})
    )

    result = await server._create_system_group(group_name, "mock_token", mock_ctx, description=description)
    assert "Successfully created system group" in result
    assert route_create.called

@pytest.mark.asyncio
async def test_list_group_systems(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "my-group"

    mock_data = [
        {"id": 1001, "name": "system1.example.com"},
        {"id": 1002, "name": "system2.example.com"}
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/systemgroup/listSystemsMinimal").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_group_systems(group_name, "mock_token")

    assert len(result) == 2
    assert result[0]['system_name'] == "system1.example.com"
    assert route.called
    assert route.calls.last.request.url.params['systemGroupName'] == group_name

@pytest.mark.asyncio
async def test_add_systems_to_group(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "my-group"
    system_ids = [1001, 1002]

    route_add = mock_uyuni.post(f"{base_url}/rhn/manager/api/systemgroup/addOrRemoveSystems").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._manage_group_systems(group_name, system_ids, True, mock_ctx)
    assert "Successfully added" in result
    assert route_add.called

    payload = json.loads(route_add.calls.last.request.content)
    assert payload['add'] is True
    assert payload['serverIds'] == system_ids

@pytest.mark.asyncio
async def test_remove_systems_from_group(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "my-group"
    system_ids = [1001]

    route_remove = mock_uyuni.post(f"{base_url}/rhn/manager/api/systemgroup/addOrRemoveSystems").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._manage_group_systems(group_name, system_ids, False, mock_ctx)
    assert "Successfully removed" in result
    assert route_remove.called

    payload = json.loads(route_remove.calls.last.request.content)
    assert payload['add'] is False
    assert payload['serverIds'] == system_ids

@pytest.mark.asyncio
async def test_get_system_event_details(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001
    event_id = 123

    mock_details = {
        "id": 123,
        "history_type": "System reboot",
        "status": "Completed",
        "summary": "System reboot scheduled by admin",
        "completed": "2025-11-27T15:37:28Z"
    }

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getEventDetails").mock(
        return_value=Response(200, json={"success": True, "result": mock_details})
    )

    result = await server._get_system_event_details(system_id, event_id, mock_ctx, "mock_token")

    assert result['id'] == 123
    assert result['history_type'] == "System reboot"
    assert route.called
    assert route.calls.last.request.url.params['sid'] == str(system_id)
    assert route.calls.last.request.url.params['eid'] == str(event_id)

@pytest.mark.asyncio
async def test_find_systems_by_name(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    name = "system1"

    mock_data = [
        {"id": 1001, "name": "system1.example.com"},
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/search/hostname").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._find_systems_by_name(name, "mock_token")

    assert len(result) == 1
    assert result[0]['system_name'] == "system1.example.com"
    assert route.called
    assert route.calls.last.request.url.params['searchTerm'] == name

@pytest.mark.asyncio
async def test_find_systems_by_ip(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    ip = "192.168.1.10"

    mock_data = [
        {"id": 1001, "name": "system1.example.com", "ip": "192.168.1.10"},
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/search/ip").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._find_systems_by_ip(ip, "mock_token")

    assert len(result) == 1
    assert result[0]['system_name'] == "system1.example.com"
    assert result[0]['ip'] == "192.168.1.10"
    assert route.called
    assert route.calls.last.request.url.params['searchTerm'] == ip

@pytest.mark.asyncio
async def test_check_all_systems_for_updates(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    # Mock list systems
    mock_systems = [{"id": 1001, "name": "system1"}]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_systems})
    )

    # Mock updates for system 1001
    mock_relevant = [{"id": 501, "advisory_name": "ADV-1"}]
    mock_unscheduled = []
    mock_cves = ["CVE-1"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_relevant})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_unscheduled})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(
        return_value=Response(200, json={"success": True, "result": mock_cves})
    )

    result = await server._check_all_systems_for_updates("mock_token", mock_ctx)

    assert 'items' in result
    assert 'meta' in result
    assert len(result['items']) == 1
    assert result['items'][0]['system_id'] == "1001"
    assert result['items'][0]['update_count'] == 1
    assert result['meta']['include_updates'] is False
    assert result['meta']['include_cves'] is False


@pytest.mark.asyncio
async def test_check_all_systems_for_updates_expanded(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_systems = [{"id": 1001, "name": "system1"}]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_systems})
    )

    mock_relevant = [{"id": 501, "advisory_name": "ADV-1"}]
    mock_unscheduled = []

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_relevant})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_unscheduled})
    )

    result = await server._check_all_systems_for_updates(
        "mock_token",
        mock_ctx,
        include_updates=True,
        include_cves=False,
        updates_per_system=10,
    )

    assert len(result['items']) == 1
    assert 'updates' in result['items'][0]
    assert result['items'][0]['updates_truncated'] is False
    assert result['meta']['include_updates'] is True
    assert result['meta']['updates_per_system'] == 10


@pytest.mark.asyncio
async def test_check_all_systems_for_updates_pagination(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_systems = [
        {"id": 1001, "name": "system1"},
        {"id": 1002, "name": "system2"},
        {"id": 1003, "name": "system3"},
    ]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_systems})
    )

    mock_relevant = [{"id": 501, "advisory_name": "ADV-1"}]
    mock_unscheduled = []

    relevant_route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_relevant})
    )
    unscheduled_route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_unscheduled})
    )

    result = await server._check_all_systems_for_updates(
        "mock_token",
        mock_ctx,
        include_updates=False,
        include_cves=False,
        system_limit=1,
        system_offset=1,
        updates_per_system=10,
    )

    assert len(relevant_route.calls) == 1
    assert len(unscheduled_route.calls) == 1
    assert relevant_route.calls.last.request.url.params['sid'] == "1002"
    assert unscheduled_route.calls.last.request.url.params['sid'] == "1002"

    assert len(result['items']) == 1
    assert result['items'][0]['system_id'] == "1002"
    assert result['meta']['total_count'] == 3
    assert result['meta']['limit'] == 1
    assert result['meta']['offset'] == 1
    assert result['meta']['next_offset'] == 2


@pytest.mark.asyncio
async def test_check_all_systems_for_updates_no_active_systems(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    result = await server._check_all_systems_for_updates("mock_token", mock_ctx)

    assert result["items"] == []
    assert result["meta"]["total_count"] == 0
    assert result["meta"]["returned_count"] == 0
    assert result["meta"]["limit"] == 25
    assert result["meta"]["offset"] == 0

@pytest.mark.asyncio
async def test_list_systems_needing_update_for_cve(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    cve = "CVE-2023-1234"

    mock_errata = [{"advisory_name": "ADV-1"}]
    mock_affected = [{"id": 1001, "name": "system1"}]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/findByCve").mock(
        return_value=Response(200, json={"success": True, "result": mock_errata})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listAffectedSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_affected})
    )

    result = await server._list_systems_needing_update_for_cve(cve, "mock_token", mock_ctx)

    assert 'items' in result
    assert 'meta' in result
    assert len(result['items']) == 1
    assert result['items'][0]['system_id'] == "1001"
    assert result['items'][0]['cve_identifier'] == cve
    assert result['meta']['returned_count'] == 1
    assert result['meta']['filters']['cve_identifier'] == cve

@pytest.mark.asyncio
async def test_list_systems_needing_reboot(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"id": 1001, "name": "system1"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSuggestedReboot").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_systems_needing_reboot("mock_token")

    assert 'items' in result
    assert 'meta' in result
    assert len(result['items']) == 1
    assert result['items'][0]['system_id'] == "1001"
    assert result['items'][0]['reboot_status'] == 'reboot_required'
    assert result['meta']['returned_count'] == 1
    assert route.called

@pytest.mark.asyncio
async def test_list_all_scheduled_actions(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"id": 123, "name": "Reboot"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/schedule/listAllActions").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_all_scheduled_actions("mock_token")

    assert 'items' in result
    assert 'meta' in result
    assert len(result['items']) == 1
    assert result['items'][0]['action_id'] == 123
    assert result['meta']['returned_count'] == 1
    assert route.called


@pytest.mark.asyncio
async def test_list_all_scheduled_actions_filters_and_pagination(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [
        {"id": 1, "name": "A", "type": "Apply states", "scheduler": "admin"},
        {"id": 2, "name": "B", "type": "Build an Image Profile", "scheduler": "admin"},
        {"id": 3, "name": "C", "type": "Apply states", "scheduler": "system"},
    ]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/schedule/listAllActions").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_all_scheduled_actions(
        "mock_token",
        limit=1,
        offset=0,
        action_types=["Apply states"],
        scheduler="admin",
    )

    assert len(result['items']) == 1
    assert result['items'][0]['type'] == "Apply states"
    assert result['items'][0]['scheduler'] == "admin"
    assert result['meta']['truncated'] is False
    assert result['meta']['filters']['action_types'] == ["Apply states"]
    assert 'statuses' not in result['meta']['filters']
    assert "Apply states" in result['meta']['observed_action_types']
    assert "admin" in result['meta']['observed_schedulers']

@pytest.mark.asyncio
async def test_list_activation_keys(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"key": "1-KEY", "description": "My Key"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/activationkey/listActivationKeys").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_activation_keys("mock_token", mock_ctx)

    assert len(result) == 1
    assert result[0]['key'] == "1-KEY"
    assert route.called

@pytest.mark.asyncio
async def test_get_unscheduled_errata(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = "1001"

    mock_data = [{"advisory_name": "ADV-1"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._get_unscheduled_errata(system_id, "mock_token")

    assert len(result) == 1
    assert result[0]['advisory_name'] == "ADV-1"
    assert result[0]['system_id'] == system_id
    assert route.called
    assert route.calls.last.request.url.params['sid'] == system_id

@pytest.mark.asyncio
async def test_list_system_groups(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"id": 10, "name": "group1", "description": "desc", "system_count": 5}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/systemgroup/listAllGroups").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_system_groups("mock_token", mock_ctx)

    assert len(result) == 1
    assert result[0]['id'] == "10"
    assert result[0]['name'] == "group1"
    assert route.called

@pytest.mark.asyncio
async def test_api_error_500(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(500, text="Internal Server Error")
    )
    with pytest.raises(HTTPError) as excinfo:
        await server._list_systems("mock_token")
    assert excinfo.value.status_code == 500
    assert f"{base_url}/rhn/manager/api/system/listSystems" in str(excinfo.value)

@pytest.mark.asyncio
async def test_auth_failure_401(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    # Override the default login mock
    mock_uyuni.post(f"{base_url}/rhn/manager/api/oidcLogin").mock(
        return_value=Response(401, text="Unauthorized")
    )
    with pytest.raises(AuthError) as excinfo:
        await server._list_systems("mock_token")
    assert excinfo.value.status_code == 401
    assert f"{base_url}/rhn/manager/api/oidcLogin" in str(excinfo.value)

@pytest.mark.asyncio
async def test_add_system_already_exists(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY", "secret")

    # Mock listSystems to return existing system
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1001, "name": "existing-system"}]})
    )

    result = await server._add_system("existing-system", "mock_token", mock_ctx, activation_key="key")
    assert "already exists" in result

@pytest.mark.asyncio
async def test_add_system_missing_ssh_key(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.delenv("UYUNI_SSH_PRIV_KEY", raising=False)

    # Mock listSystems (empty)
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    result = await server._add_system("new-system", "mock_token", mock_ctx, activation_key="key")
    assert "UYUNI_SSH_PRIV_KEY environment variable is not set" in result

@pytest.mark.asyncio
async def test_add_system_timeout(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY", "secret")

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    # Mock bootstrap to raise TimeoutException
    mock_uyuni.post(f"{base_url}/rhn/manager/api/system/bootstrapWithPrivateSshKey").mock(
        side_effect=httpx.TimeoutException("Timeout")
    )

    result = await server._add_system("new-system", "mock_token", mock_ctx, activation_key="key")
    assert "process started" in result
    assert "may take some time" in result

@pytest.mark.asyncio
async def test_remove_system_not_found(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 9999

    # Mock listSystems (does not contain 9999)
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1001, "name": "sys1"}]})
    )

    result = await server._remove_system(system_id, mock_ctx, "mock_token")
    assert f"System with ID {system_id} not found" in result

@pytest.mark.asyncio
async def test_resolve_system_id_by_name_not_found(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    name = "non-existent"

    # Mock getId returning empty list
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getId").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    with pytest.raises(NotFoundError):
        await server._get_system_details(name, mock_ctx, "mock_token")

@pytest.mark.asyncio
async def test_resolve_system_id_by_name_multiple_found(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    name = "ambiguous"

    # Mock getId returning multiple
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getId").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1}, {"id": 2}]})
    )

    with pytest.raises(UnexpectedResponse) as excinfo:
        await server._get_system_details(name, mock_ctx, "mock_token")
    assert "Multiple systems found" in str(excinfo.value)
    assert f"{base_url}/rhn/manager/api/system/getId" in str(excinfo.value)

@pytest.mark.asyncio
async def test_malformed_api_response(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]

    # Mock listSystems returning something that is not a list
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": "not-a-list"})
    )

    result = await server._list_systems("mock_token")
    assert result == []

def test_write_tool_disabled(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_WRITE_TOOLS_ENABLED", False)

    def dummy_func():
        pass

    # When disabled, decorator returns original function
    decorated = server.write_tool()(dummy_func)
    assert decorated is dummy_func

def test_write_tool_enabled(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_WRITE_TOOLS_ENABLED", True)

    # Mock mcp.tool to verify it wraps the function
    mock_tool_decorator = MagicMock(side_effect=lambda f: f)
    mock_tool_factory = MagicMock(return_value=mock_tool_decorator)

    with patch.object(server.mcp, 'tool', mock_tool_factory):
        def dummy_func():
            pass

        server.write_tool()(dummy_func)
        assert mock_tool_factory.called

@pytest.mark.asyncio
async def test_auth_middleware_extracts_token():
    middleware = server.AuthTokenMiddleware()

    mock_ctx = MagicMock()
    # Mock the nested structure: ctx.fastmcp_context.request_context.request.headers
    mock_ctx.fastmcp_context.request_context.request.headers = {'authorization': 'Bearer my-token'}
    mock_ctx.fastmcp_context.set_state = AsyncMock()

    async def call_next(ctx):
        return "ok"

    await middleware.on_call_tool(mock_ctx, call_next)

    mock_ctx.fastmcp_context.set_state.assert_awaited_once_with('token', 'my-token')

@pytest.mark.asyncio
async def test_auth_middleware_missing_header():
    middleware = server.AuthTokenMiddleware()

    mock_ctx = MagicMock()
    mock_ctx.fastmcp_context.request_context.request.headers = {}
    mock_ctx.fastmcp_context.set_state = AsyncMock()

    async def call_next(ctx):
        return "ok"

    await middleware.on_call_tool(mock_ctx, call_next)

    mock_ctx.fastmcp_context.set_state.assert_awaited_once_with('token', None)

@pytest.mark.asyncio
async def test_auth_middleware_malformed_header():
    middleware = server.AuthTokenMiddleware()

    mock_ctx = MagicMock()
    mock_ctx.fastmcp_context.request_context.request.headers = {'authorization': 'Basic user:pass'}
    mock_ctx.fastmcp_context.set_state = AsyncMock()

    async def call_next(ctx):
        return "ok"

    await middleware.on_call_tool(mock_ctx, call_next)

    mock_ctx.fastmcp_context.set_state.assert_awaited_once_with('token', None)

def test_main_cli_stdio(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_TRANSPORT", "stdio")

    with patch.object(server.mcp, 'run') as mock_run:
        server.main_cli()
        mock_run.assert_called_with(transport="stdio")

def test_main_cli_http(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_TRANSPORT", "http")
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_HOST", "localhost")
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_PORT", 8000)
    monkeypatch.setitem(server.CONFIG, "AUTH_SERVER", None)

    with patch.object(server.mcp, 'run') as mock_run:
        server.main_cli()
        mock_run.assert_called_with(transport="streamable-http", host="localhost", port=8000)

def test_get_public_base_url_prefers_explicit_public_url():
    config = {
        "UYUNI_MCP_HOST": "0.0.0.0",
        "UYUNI_MCP_PORT": 8000,
        "UYUNI_MCP_PUBLIC_URL": "https://mcp.example.com/",
    }

    assert server._get_public_base_url(config) == "https://mcp.example.com"

def test_get_public_base_url_rewrites_wildcard_bind_host():
    config = {
        "UYUNI_MCP_HOST": "0.0.0.0",
        "UYUNI_MCP_PORT": 8000,
        "UYUNI_MCP_PUBLIC_URL": None,
    }

    assert server._get_public_base_url(config) == "http://127.0.0.1:8000"

@pytest.mark.asyncio
async def test_list_ansible_control_nodes_logs_in_once(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    login_route = mock_uyuni.post(f"{base_url}/rhn/manager/api/oidcLogin")
    systems_route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystemsWithEntitlement").mock(
        return_value=Response(200, json={"success": True, "result": [
            {"id": 1001, "name": "cn1.example.com"},
            {"id": 1002, "name": "cn2.example.com"},
        ]})
    )
    paths_route = mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/listAnsiblePaths").mock(
        side_effect=[
            Response(200, json={"success": True, "result": [
                {"id": 5, "type": "playbook", "server_id": 1001, "path": "/srv/playbooks"},
                {"id": 6, "type": "inventory", "server_id": 1001, "path": "/etc/ansible/hosts"},
            ]}),
            Response(200, json={"success": True, "result": []}),
        ]
    )

    result = await server._list_ansible_control_nodes("mock_token")

    assert result == [
        {
            'system_id': "1001",
            'system_name': "cn1.example.com",
            'playbook_paths': [{'path_id': "5", 'path': "/srv/playbooks"}],
            'inventory_paths': [{'path_id': "6", 'path': "/etc/ansible/hosts"}],
        },
        {
            'system_id': "1002",
            'system_name': "cn2.example.com",
            'playbook_paths': [],
            'inventory_paths': [],
        },
    ]
    assert systems_route.calls.last.request.url.params["entitlementName"] == "ansible_control_node"
    assert [c.request.url.params["controlNodeId"] for c in paths_route.calls] == ["1001", "1002"]
    assert login_route.call_count == 1

@pytest.mark.asyncio
async def test_list_ansible_control_nodes_none(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystemsWithEntitlement").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    assert await server._list_ansible_control_nodes("mock_token") == []

@pytest.mark.asyncio
async def test_list_ansible_playbooks(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    route = mock_uyuni.post(f"{base_url}/rhn/manager/api/ansible/discoverPlaybooks").mock(
        return_value=Response(200, json={"success": True, "result": {
            "/etc/ansible/playbooks": {
                "site/facts.yml": {"fullpath": "/etc/ansible/playbooks/site/facts.yml"},
                "lamp/site.yml": {"fullpath": "/etc/ansible/playbooks/lamp/site.yml", "custom_inventory": "/etc/ansible/playbooks/lamp/hosts"},
            }
        }})
    )

    result = await server._list_ansible_playbooks(5, "mock_token")

    # sorted by full path, whatever order the API returns
    assert result == [
        {'playbook': "lamp/site.yml", 'full_path': "/etc/ansible/playbooks/lamp/site.yml", 'inventory': "/etc/ansible/playbooks/lamp/hosts"},
        {'playbook': "site/facts.yml", 'full_path': "/etc/ansible/playbooks/site/facts.yml", 'inventory': ""},
    ]
    assert json.loads(route.calls.last.request.content) == {"pathId": 5}

def _says_yes(mock_ctx):
    """A client that can ask and whose user confirms."""
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock(return_value=MagicMock(action="accept", data={"approve": True}))
    return mock_ctx

def _mock_inventory_path(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    lookup_route = mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/lookupAnsiblePathById").mock(
        return_value=Response(200, json={"success": True, "result": {
            "id": 6, "type": "inventory", "server_id": 1001, "path": "/etc/ansible/hosts",
        }})
    )
    inventory_route = mock_uyuni.post(f"{base_url}/rhn/manager/api/ansible/introspectInventory").mock(
        return_value=Response(200, json={"success": True, "result": {
            "_meta": {
                "hostvars": {"leap.example.com": {"ansible_user": "root", "db_password": "secret"}},
                "profile": "inventory_legacy",
            },
            "all": {"children": ["ungrouped", "site"]},
            "site": {"children": ["web", "db"]},
            "web": {"hosts": ["leap.example.com", "alma.example.com"], "vars": {"api_token": "secret"}},
            "db": {"hosts": ["leap.example.com"]},
        }})
    )
    return lookup_route, inventory_route

@pytest.mark.asyncio
async def test_get_ansible_inventory_drops_variables(mock_uyuni, mock_ctx):
    login_route = mock_uyuni.post(f"{server.CONFIG['UYUNI_SERVER']}/rhn/manager/api/oidcLogin")
    lookup_route, inventory_route = _mock_inventory_path(mock_uyuni)

    result = await server._get_ansible_inventory(6, "mock_token", _says_yes(mock_ctx))

    assert result == {
        'path_id': "6",
        'path': "/etc/ansible/hosts",
        'system_id': "1001",
        'groups': {
            'all': {'children': ["ungrouped", "site"], 'host_count': 0},
            'site': {'children': ["web", "db"], 'host_count': 0},
            'web': {'children': [], 'host_count': 2},
            'db': {'children': [], 'host_count': 1},
        },
        'hosts': [
            {'host': "alma.example.com", 'groups': ["web"]},
            {'host': "leap.example.com", 'groups': ["web", "db"]},
        ],
    }
    assert "secret" not in json.dumps(result)
    assert lookup_route.calls.last.request.url.params["pathId"] == "6"
    assert json.loads(inventory_route.calls.last.request.content) == {"pathId": 6}
    assert login_route.call_count == 1

@pytest.mark.asyncio
@pytest.mark.parametrize("elicit_result,executed", [
    (MagicMock(action="accept", data={"approve": True}), True),
    (MagicMock(action="accept", data={"approve": False}), False),
    (MagicMock(action="decline", data=None), False),
    (MagicMock(action="cancel", data=None), False),
])
async def test_get_ansible_inventory_asks_before_running(mock_uyuni, mock_ctx, elicit_result, executed):
    _, inventory_route = _mock_inventory_path(mock_uyuni)
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock(return_value=elicit_result)

    result = await server._get_ansible_inventory(6, "mock_token", mock_ctx)

    prompt = mock_ctx.elicit.call_args.args[0]
    assert "as root" in prompt and "/etc/ansible/hosts" in prompt and "1001" in prompt
    assert inventory_route.called is executed
    if executed:
        assert len(result['hosts']) == 2
        assert 'message' not in result
    else:
        assert result == {
            'path_id': "6", 'path': "/etc/ansible/hosts", 'system_id': "1001",
            'groups': {}, 'hosts': [], 'message': "Operation cancelled.",
        }

@pytest.mark.asyncio
async def test_get_ansible_inventory_refuses_a_client_that_cannot_ask(mock_uyuni, mock_ctx):
    _, inventory_route = _mock_inventory_path(mock_uyuni)
    mock_ctx.session.check_client_capability.return_value = False
    mock_ctx.elicit = AsyncMock()

    result = await server._get_ansible_inventory(6, "mock_token", mock_ctx)

    assert "cannot ask for a confirmation" in result['message'] and "Nothing was run" in result['message']
    assert result['hosts'] == [] and result['groups'] == {}
    mock_ctx.elicit.assert_not_called()
    assert not inventory_route.called

@pytest.mark.asyncio
async def test_get_ansible_inventory_refuses_playbook_path(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/lookupAnsiblePathById").mock(
        return_value=Response(200, json={"success": True, "result": {
            "id": 5, "type": "playbook", "server_id": 1001, "path": "/srv/playbooks",
        }})
    )
    inventory_route = mock_uyuni.post(f"{base_url}/rhn/manager/api/ansible/introspectInventory")
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock()

    result = await server._get_ansible_inventory(5, "mock_token", mock_ctx)

    assert result == {
        'path_id': "5", 'path': "/srv/playbooks", 'system_id': "1001",
        'groups': {}, 'hosts': [], 'message': "Path 5 is not an inventory path. Nothing was run.",
    }
    mock_ctx.elicit.assert_not_called()
    assert not inventory_route.called

@pytest.mark.asyncio
async def test_get_ansible_inventory_unknown_path_runs_nothing(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/lookupAnsiblePathById").mock(
        return_value=Response(200, json={"success": False, "message": "Unable to find ansible path id: 99"})
    )
    inventory_route = mock_uyuni.post(f"{base_url}/rhn/manager/api/ansible/introspectInventory")
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock()

    with pytest.raises(UnexpectedResponse):
        await server._get_ansible_inventory(99, "mock_token", mock_ctx)

    mock_ctx.elicit.assert_not_called()
    assert not inventory_route.called

@pytest.mark.asyncio
async def test_ansible_post_helpers_refused_with_write_tools_disabled(mock_uyuni, mock_ctx, monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_WRITE_TOOLS_ENABLED", False)
    from mcp_server_uyuni.errors import APIError
    _, inventory_route = _mock_inventory_path(mock_uyuni)

    with pytest.raises(APIError):
        await server._list_ansible_playbooks(5, "mock_token")
    with pytest.raises(APIError):
        await server._get_ansible_inventory(6, "mock_token", _says_yes(mock_ctx))
    assert not inventory_route.called

@pytest.mark.asyncio
async def test_ansible_tools_registered():
    tools = {tool.name for tool in await server.mcp.list_tools()}

    # test module runs with write tools enabled, so the POST tools are visible here
    assert {"list_ansible_control_nodes", "list_ansible_playbooks", "get_ansible_inventory"} <= tools

@pytest.mark.asyncio
async def test_ansible_tools_annotations():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}

    def hints(name):
        annotations = tools[name].annotations
        return (annotations.readOnlyHint, annotations.idempotentHint, annotations.destructiveHint)

    assert hints("list_ansible_control_nodes") == (True, True, None)
    assert hints("list_ansible_playbooks") == (True, True, None)
    # reading an inventory makes the control node execute it, so it is not marked read-only
    assert hints("get_ansible_inventory") == (False, None, False)

@pytest.mark.asyncio
async def test_list_ansible_playbooks_accepts_listed_path_id_and_pages(mock_uyuni):
    # list_ansible_control_nodes returns path ids as strings; the follow-up tools must take them as given.
    from fastmcp import Client
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.post(f"{base_url}/rhn/manager/api/login").mock(
        return_value=Response(200, json={"success": True})
    )
    route = mock_uyuni.post(f"{base_url}/rhn/manager/api/ansible/discoverPlaybooks").mock(
        return_value=Response(200, json={"success": True, "result": {"/etc/ansible/playbooks": {
            f"play{n}.yml": {"fullpath": f"/etc/ansible/playbooks/play{n}.yml"} for n in range(3)
        }}})
    )

    async with Client(server.mcp) as client:
        result = await client.call_tool("list_ansible_playbooks", {"path_id": "2", "limit": 2})
        empty = await client.call_tool("list_ansible_playbooks", {"path_id": "2", "offset": 3})

    assert json.loads(route.calls[0].request.content) == {"pathId": 2}
    assert result.data['path_id'] == "2"
    assert [item['playbook'] for item in result.data['items']] == ["play0.yml", "play1.yml"]
    assert result.data['meta']['total_count'] == 3 and result.data['meta']['next_offset'] == 2
    # nothing on the page: the result still names the path
    assert empty.data['path_id'] == "2" and empty.data['items'] == []

@pytest.mark.asyncio
@pytest.mark.parametrize("approve,executed", [(True, True), (False, False)])
async def test_get_ansible_inventory_elicits_through_mcp(mock_uyuni, approve, executed):
    # A real MCP client that supports elicitation: the tool must wait for the answer before the POST.
    from fastmcp import Client
    from fastmcp.client.elicitation import ElicitResult
    mock_uyuni.post(f"{server.CONFIG['UYUNI_SERVER']}/rhn/manager/api/login").mock(
        return_value=Response(200, json={"success": True})
    )
    _, inventory_route = _mock_inventory_path(mock_uyuni)
    prompts = []

    async def answer(message, response_type, params, context):
        prompts.append(message)
        assert not inventory_route.called
        if approve:
            return response_type(approve=True)
        return ElicitResult(action="decline")

    async with Client(server.mcp, elicitation_handler=answer) as client:
        result = await client.call_tool("get_ansible_inventory", {"path_id": "6", "limit": 1})

    assert len(prompts) == 1 and "as root" in prompts[0]
    assert inventory_route.called is executed
    if executed:
        assert result.data['items'] == [{'host': "alma.example.com", 'groups': ["web"]}]
        assert result.data['meta']['total_count'] == 2 and result.data['meta']['truncated'] is True
        assert result.data['groups']['web'] == {'children': [], 'host_count': 2}
    else:
        assert result.data['message'] == "Operation cancelled."
        assert result.data['items'] == [] and result.data['meta']['total_count'] == 0

@pytest.mark.asyncio
async def test_get_ansible_inventory_refuses_through_mcp_without_elicitation(mock_uyuni):
    # A real MCP client that cannot be asked: the tool answers with a refusal and the POST never happens.
    from fastmcp import Client
    mock_uyuni.post(f"{server.CONFIG['UYUNI_SERVER']}/rhn/manager/api/login").mock(
        return_value=Response(200, json={"success": True})
    )
    _, inventory_route = _mock_inventory_path(mock_uyuni)

    async with Client(server.mcp) as client:
        result = await client.call_tool("get_ansible_inventory", {"path_id": "6"})

    assert "cannot ask for a confirmation" in result.data['message']
    assert result.data['items'] == [] and not inventory_route.called

@pytest.fixture
def server_log(caplog, monkeypatch):
    """caplog for the server's logger, which does not propagate to the root logger."""
    monkeypatch.setattr(server.logger, "propagate", True)
    return caplog

@pytest.mark.asyncio
async def test_list_ansible_control_nodes_skips_items_without_id(mock_uyuni, server_log):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystemsWithEntitlement").mock(
        return_value=Response(200, json={"success": True, "result": [{"name": "no-id.example.com"}, {"id": 1001, "name": "cn1.example.com"}]})
    )
    paths_route = mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/listAnsiblePaths").mock(
        return_value=Response(200, json={"success": True, "result": [
            {"type": "inventory", "server_id": 1001, "path": "/etc/ansible/no-id"},
            "not-a-path",
            {"id": 6, "type": "inventory", "server_id": 1001, "path": "/etc/ansible/hosts"},
        ]})
    )

    result = await server._list_ansible_control_nodes("mock_token")

    assert result == [{
        'system_id': "1001",
        'system_name': "cn1.example.com",
        'playbook_paths': [],
        'inventory_paths': [{'path_id': "6", 'path': "/etc/ansible/hosts"}],
    }]
    assert paths_route.call_count == 1
    assert "no-id.example.com" in server_log.text and "/etc/ansible/no-id" in server_log.text and "not-a-path" in server_log.text

@pytest.mark.asyncio
async def test_list_ansible_control_nodes_path_listing_fails(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystemsWithEntitlement").mock(
        return_value=Response(200, json={"success": True, "result": [
            {"id": 1001, "name": "cn1.example.com"},
            {"id": 1002, "name": "cn2.example.com"},
        ]})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/listAnsiblePaths").mock(
        side_effect=[
            Response(200, json={"success": True, "result": []}),
            Response(200, json={"success": False, "message": "No such system - sid = 1002"}),
        ]
    )

    # A failure on one node reaches the caller, as other API failures do, instead of a partial list.
    with pytest.raises(UnexpectedResponse, match="No such system"):
        await server._list_ansible_control_nodes("mock_token")

@pytest.mark.asyncio
@pytest.mark.parametrize("systems,paths,expected,log", [
    ("not a list", [], [], "Expected a list of control nodes"),
    ([{"id": 1001, "name": "cn1.example.com"}], {"unexpected": "dict"},
     [{'system_id': "1001", 'system_name': "cn1.example.com", 'playbook_paths': [], 'inventory_paths': []}],
     "Expected a list of Ansible paths for control node 1001"),
])
async def test_list_ansible_control_nodes_non_list_results(mock_uyuni, server_log, systems, paths, expected, log):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystemsWithEntitlement").mock(
        return_value=Response(200, json={"success": True, "result": systems})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/listAnsiblePaths").mock(
        return_value=Response(200, json={"success": True, "result": paths})
    )

    assert await server._list_ansible_control_nodes("mock_token") == expected
    assert log in server_log.text

@pytest.mark.asyncio
@pytest.mark.parametrize("api_result,expected,log", [
    (["not", "a", "dict"], [], "Expected a dict of discovered playbooks"),
    ({"/etc/ansible/playbooks": ["not", "a", "dict"], "/srv/playbooks": {"site.yml": {"fullpath": "/srv/playbooks/site.yml"}}},
     [{'playbook': "site.yml", 'full_path': "/srv/playbooks/site.yml", 'inventory': ""}], "Unexpected item format in discovered playbooks"),
    ({"/srv/playbooks": {"site.yml": "not a dict"}},
     [{'playbook': "site.yml", 'full_path': "", 'inventory': ""}], "Unexpected details for playbook site.yml"),
])
async def test_list_ansible_playbooks_unexpected_result(mock_uyuni, server_log, api_result, expected, log):
    mock_uyuni.post(f"{server.CONFIG['UYUNI_SERVER']}/rhn/manager/api/ansible/discoverPlaybooks").mock(
        return_value=Response(200, json={"success": True, "result": api_result})
    )

    assert await server._list_ansible_playbooks(5, "mock_token") == expected
    assert log in server_log.text

@pytest.mark.asyncio
async def test_get_ansible_inventory_unexpected_result(mock_uyuni, mock_ctx, server_log):
    _, inventory_route = _mock_inventory_path(mock_uyuni)
    inventory_route.mock(return_value=Response(200, json={"success": True, "result": ["not", "a", "dict"]}))

    result = await server._get_ansible_inventory(6, "mock_token", _says_yes(mock_ctx))

    assert result['groups'] == {} and result['hosts'] == []
    assert "Nothing was listed" in result['message']
    assert "Expected a dict" in server_log.text

@pytest.mark.asyncio
async def test_get_ansible_inventory_skips_malformed_group(mock_uyuni, mock_ctx, server_log):
    _, inventory_route = _mock_inventory_path(mock_uyuni)
    inventory_route.mock(return_value=Response(200, json={"success": True, "result": {
        "web": ["not", "a", "dict"],
        "db": {"hosts": ["leap.example.com"]},
    }}))

    result = await server._get_ansible_inventory(6, "mock_token", _says_yes(mock_ctx))

    assert result['groups'] == {'db': {'children': [], 'host_count': 1}}
    assert result['hosts'] == [{'host': "leap.example.com", 'groups': ["db"]}]
    assert "inventory group web" in server_log.text

@pytest.mark.asyncio
async def test_get_ansible_inventory_lookup_without_server_id(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/ansible/lookupAnsiblePathById").mock(
        return_value=Response(200, json={"success": True, "result": {"id": 6, "type": "inventory", "path": "/etc/ansible/hosts"}})
    )
    inventory_route = mock_uyuni.post(f"{base_url}/rhn/manager/api/ansible/introspectInventory")
    mock_ctx.session.check_client_capability.return_value = True
    mock_ctx.elicit = AsyncMock(return_value=MagicMock(action="decline", data=None))

    result = await server._get_ansible_inventory(6, "mock_token", mock_ctx)

    assert 'system_id' not in result
    assert "None" not in mock_ctx.elicit.call_args.args[0]
    assert not inventory_route.called

@pytest.mark.asyncio
@pytest.mark.parametrize("tool,route_path", [
    ("list_ansible_playbooks", "discoverPlaybooks"),
    ("get_ansible_inventory", "introspectInventory"),
])
async def test_ansible_post_salt_fault_reaches_caller(mock_uyuni, mock_ctx, tool, route_path):
    _mock_inventory_path(mock_uyuni)
    mock_uyuni.post(f"{server.CONFIG['UYUNI_SERVER']}/rhn/manager/api/ansible/{route_path}").mock(
        return_value=Response(200, json={"success": False, "message": "Salt fault: Minion not responding"})
    )

    with pytest.raises(UnexpectedResponse, match="Minion not responding"):
        if tool == "list_ansible_playbooks":
            await server._list_ansible_playbooks(5, "mock_token")
        else:
            await server._get_ansible_inventory(6, "mock_token", _says_yes(mock_ctx))
