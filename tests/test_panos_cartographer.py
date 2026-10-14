"""
Unit tests for core.panos.cartographer.
Tests deterministic topology generation, multi-interface support (Ethernet, subinterfaces, tunnel, loopback),
client acquisition error resilience, metadata sanitization, and node deduplication.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from core.panos.cartographer import Cartographer


@pytest.fixture
def mock_client_pool():
    with patch("core.panos.cartographer.PanOSClientPool.get_instance") as mock_get_pool:
        mock_pool = MagicMock()
        mock_client = MagicMock()
        mock_client.hostname = "192.168.1.1"
        mock_client.label = "HQ-Firewall"
        mock_client.device_name = "fw-hq"
        mock_pool.get_client.return_value = mock_client
        mock_get_pool.return_value = mock_pool
        yield mock_pool, mock_client


def test_build_graph_handles_client_acquisition_failure():
    """Verify H2: ValueError or missing client produces valid JSON error response."""
    with patch("core.panos.cartographer.PanOSClientPool.get_instance") as mock_get_pool:
        mock_pool = MagicMock()
        mock_pool.get_client.side_effect = ValueError("Device 'nonexistent' not found in registry")
        mock_get_pool.return_value = mock_pool

        cartographer = Cartographer(target_device="nonexistent")
        graph_json = cartographer.build_graph()

        data = json.loads(graph_json)
        assert data["nodes"] == []
        assert data["edges"] == []
        assert "Device 'nonexistent' not found" in data["error"]


def test_build_graph_sanitizes_metadata_source(mock_client_pool):
    """Verify H1: source metadata uses label instead of raw hostname."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result><config></config></result></response>")

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    assert data["metadata"]["source"] == "HQ-Firewall"
    assert "192.168.1.1" not in graph_json


def test_build_graph_extracts_multi_interface_families(mock_client_pool):
    """Verify M1: physical ethernet, subinterfaces, tunnel, and loopback are all extracted."""
    _, mock_client = mock_client_pool

    sample_config_xml = """
    <response status="success">
      <result>
        <config>
          <devices>
            <entry>
              <network>
                <interface>
                  <ethernet>
                    <entry name="ethernet1/1">
                      <layer3>
                        <ip><entry name="10.0.1.1/24"/></ip>
                        <units>
                          <entry name="ethernet1/1.10">
                            <ip><entry name="10.0.10.1/24"/></ip>
                          </entry>
                        </units>
                      </layer3>
                    </entry>
                  </ethernet>
                  <tunnel>
                    <units>
                      <entry name="tunnel.1">
                        <ip><entry name="10.255.0.1/30"/></ip>
                      </entry>
                    </units>
                  </tunnel>
                  <loopback>
                    <units>
                      <entry name="loopback.1">
                        <ip><entry name="1.1.1.1/32"/></ip>
                      </entry>
                    </units>
                  </loopback>
                </interface>
              </network>
              <vsys>
                <entry>
                  <zone>
                    <entry name="Trust">
                      <network>
                        <layer3>
                          <member>ethernet1/1</member>
                          <member>ethernet1/1.10</member>
                        </layer3>
                      </network>
                    </entry>
                    <entry name="VPN">
                      <network>
                        <layer3>
                          <member>tunnel.1</member>
                          <member>loopback.1</member>
                        </layer3>
                      </network>
                    </entry>
                  </zone>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
      </result>
    </response>
    """
    mock_client.execute_op.return_value = (200, sample_config_xml)

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    node_labels = [n["label"] for n in data["nodes"]]
    assert any("ethernet1/1 (10.0.1.1/24)" in l for l in node_labels)
    assert any("ethernet1/1.10 (10.0.10.1/24)" in l for l in node_labels)
    assert any("tunnel.1 (10.255.0.1/30)" in l for l in node_labels)
    assert any("loopback.1 (1.1.1.1/32)" in l for l in node_labels)

    assert data["metadata"]["zones_mapped"] == 2
    assert data["metadata"]["interfaces_mapped"] == 4


def test_build_graph_node_deduplication(mock_client_pool):
    """Verify Self-Audit 1: duplicate zone or interface definitions do not produce duplicate node IDs."""
    _, mock_client = mock_client_pool

    config_with_dups = """
    <response status="success">
      <result>
        <config>
          <devices>
            <entry>
              <network>
                <interface>
                  <ethernet>
                    <entry name="ethernet1/1">
                      <layer3><ip><entry name="10.0.0.1/24"/></ip></layer3>
                    </entry>
                  </ethernet>
                </interface>
              </network>
              <vsys>
                <entry>
                  <zone>
                    <entry name="Trust">
                      <network><layer3><member>ethernet1/1</member></layer3></network>
                    </entry>
                    <entry name="Trust">
                      <network><layer3><member>ethernet1/1</member></layer3></network>
                    </entry>
                  </zone>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
      </result>
    </response>
    """
    mock_client.execute_op.return_value = (200, config_with_dups)

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    node_ids = [n["id"] for n in data["nodes"]]
    assert len(node_ids) == len(set(node_ids))


def test_build_graph_extracts_posture_and_system_telemetry(mock_client_pool):
    """Verify Cartographer compiles telemetry, posture, mgmt overlap, and license/admin nodes."""
    _, mock_client = mock_client_pool

    config_xml = """
    <response status="success">
      <result>
        <config>
          <devices>
            <entry>
              <network>
                <interface>
                  <ethernet>
                    <entry name="ethernet1/2">
                      <layer3>
                        <ip><entry name="192.168.1.1/24"/></ip>
                        <interface-management-profile>ping-response-pages</interface-management-profile>
                      </layer3>
                    </entry>
                  </ethernet>
                </interface>
                <profiles>
                  <interface-management-profile>
                    <entry name="ping-response-pages">
                      <ping>yes</ping>
                      <response-pages>yes</response-pages>
                    </entry>
                  </interface-management-profile>
                </profiles>
              </network>
              <vsys>
                <entry>
                  <zone>
                    <entry name="Trust">
                      <network><layer3><member>ethernet1/2</member></layer3></network>
                    </entry>
                  </zone>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
      </result>
    </response>
    """

    system_xml = """
    <response status="success">
      <result>
        <system>
          <hostname>firewall-a</hostname>
          <ip-address>192.168.1.254</ip-address>
          <netmask>255.255.255.0</netmask>
          <default-gateway>192.168.1.1</default-gateway>
          <time>Mon Oct 12 07:04:10 2026</time>
          <model>PA-VM</model>
          <sw-version>10.0.12-h3</sw-version>
          <threat-version>8792-8469</threat-version>
          <threat-release-date>2023/12/19 22:38:55 UTC</threat-release-date>
        </system>
      </result>
    </response>
    """

    license_xml = """
    <response status="success">
      <result>
        <licenses>
          <entry>
            <feature>Threat Prevention</feature>
            <expires>May 21, 2026</expires>
            <expired>yes</expired>
          </entry>
          <entry>
            <feature>WildFire License</feature>
            <expires>May 21, 2026</expires>
            <expired>yes</expired>
          </entry>
          <entry>
            <feature>GlobalProtect Portal</feature>
            <expires>Never</expires>
            <expired>no</expired>
          </entry>
        </licenses>
      </result>
    </response>
    """

    admins_xml = """
    <response status="success">
      <result>
        <admins>
          <entry>
            <admin>admin</admin>
            <from>192.168.1.20</from>
            <type>Web</type>
            <idle-for>07:49:59s</idle-for>
            <session-expiry>1200s</session-expiry>
          </entry>
        </admins>
      </result>
    </response>
    """

    def mock_op(cmd):
        if "running" in cmd:
            return (200, config_xml)
        elif "system" in cmd:
            return (200, system_xml)
        elif "license" in cmd:
            return (200, license_xml)
        elif "admins" in cmd:
            return (200, admins_xml)
        return (400, "<response status='error'></response>")

    mock_client.execute_op.side_effect = mock_op

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    posture = data["metadata"]["posture"]
    assert posture["panos_version"] == "10.0.12-h3"
    assert posture["model"] == "PA-VM"
    assert posture["is_eol"] is True
    assert posture["is_threat_stale"] is True
    assert posture["threat_stale_days"] > 1000
    assert posture["mgmt_ip"] == "192.168.1.254"
    assert posture["mgmt_dataplane_overlap"] is True
    assert posture["overlap_interfaces"] == ["ethernet1/2"]
    assert posture["expired_licenses"] == ["Threat Prevention", "WildFire License"]
    assert posture["active_licenses"] == ["GlobalProtect Portal"]
    assert len(posture["active_admin_sessions"]) == 1
    assert posture["active_admin_sessions"][0]["admin"] == "admin"

    # Verify node extraction
    nodes_by_id = {n["id"]: n for n in data["nodes"]}
    assert "interface_mgmt" in nodes_by_id
    assert nodes_by_id["interface_mgmt"]["type"] == "management_interface"

    assert "lic_threat_prevention" in nodes_by_id
    assert nodes_by_id["lic_threat_prevention"]["type"] == "expired_license"

    assert "admin_admin_192_168_1_20" in nodes_by_id
    assert nodes_by_id["admin_admin_192_168_1_20"]["type"] == "admin_session"

    assert "subnet_ethernet1_2" in nodes_by_id
    assert nodes_by_id["subnet_ethernet1_2"]["mgmt_profile"] == "ping-response-pages"
    assert nodes_by_id["subnet_ethernet1_2"]["mgmt_services"] == ["ping", "response-pages"]

    # Verify edge extraction
    edge_tuples = [(e["source"], e["target"], e["label"]) for e in data["edges"]]
    assert ("firewall", "interface_mgmt", "managed_by") in edge_tuples
    assert ("interface_mgmt", "subnet_ethernet1_2", "overlaps_subnet") in edge_tuples
    assert ("firewall", "lic_threat_prevention", "license_expired") in edge_tuples
    assert ("firewall", "admin_admin_192_168_1_20", "active_admin") in edge_tuples


def test_build_graph_fail_soft_telemetry_errors(mock_client_pool):
    """Verify Cartographer builds base graph even if telemetry endpoints fail or raise exceptions."""
    _, mock_client = mock_client_pool

    config_xml = """
    <response status="success">
      <result>
        <config>
          <devices>
            <entry>
              <network>
                <interface>
                  <ethernet>
                    <entry name="ethernet1/1">
                      <layer3><ip><entry name="10.0.0.1/24"/></ip></layer3>
                    </entry>
                  </ethernet>
                </interface>
              </network>
              <vsys>
                <entry>
                  <zone>
                    <entry name="Trust">
                      <network><layer3><member>ethernet1/1</member></layer3></network>
                    </entry>
                  </zone>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
      </result>
    </response>
    """

    def mock_op_with_errors(cmd):
        if "running" in cmd:
            return (200, config_xml)
        elif "system" in cmd:
            raise ConnectionResetError("Connection dropped by peer")
        elif "license" in cmd:
            return (500, "<response status='error'><msg>Server internal error</msg></response>")
        elif "admins" in cmd:
            return (403, "<response status='error'><msg>Forbidden</msg></response>")
        return (400, "Bad Request")

    mock_client.execute_op.side_effect = mock_op_with_errors

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    assert "error" not in data
    assert len(data["nodes"]) >= 3  # firewall, zone, subnet
    assert data["metadata"]["zones_mapped"] == 1
    assert data["metadata"]["interfaces_mapped"] == 1

    posture = data["metadata"]["posture"]
    assert posture["panos_version"] is None
    assert posture["is_eol"] is False
    assert posture["expired_licenses"] == []
    assert posture["active_admin_sessions"] == []


def test_build_graph_extracts_virtual_router(mock_client_pool):
    """Verify Cartographer auto-discovers named virtual routers and updates client VR cache."""
    _, mock_client = mock_client_pool
    mock_client.virtual_router = "default"
    mock_client._cached_vr = "default"

    config_xml = """
    <response status="success">
      <result>
        <config>
          <devices>
            <entry>
              <network>
                <virtual-router>
                  <entry name="lab-vr">
                    <protocol><bgp><enable>no</enable></bgp></protocol>
                  </entry>
                </virtual-router>
                <interface>
                  <ethernet>
                    <entry name="ethernet1/1">
                      <layer3><ip><entry name="10.0.1.1/24"/></ip></layer3>
                    </entry>
                  </ethernet>
                </interface>
              </network>
              <vsys>
                <entry>
                  <zone>
                    <entry name="Trust">
                      <network><layer3><member>ethernet1/1</member></layer3></network>
                    </entry>
                  </zone>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
      </result>
    </response>
    """
    mock_client.execute_op.return_value = (200, config_xml)

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    posture = data["metadata"]["posture"]
    assert posture["virtual_router"] == "lab-vr"
    assert posture["virtual_routers"] == ["lab-vr"]
    assert mock_client._cached_vr == "lab-vr"
    assert mock_client.virtual_router == "lab-vr"


def test_build_graph_extracts_permitted_ips_and_saml_profiles(mock_client_pool):
    """Verify Cartographer extracts management permitted-ips and SAML certificate validation status."""
    _, mock_client = mock_client_pool

    config_xml = """
    <response status="success">
      <result>
        <config>
          <devices>
            <entry name="localhost.localdomain">
              <deviceconfig>
                <system>
                  <permitted-ip>
                    <entry name="192.168.1.50/32"/>
                    <entry name="192.168.1.20/32"/>
                  </permitted-ip>
                </system>
              </deviceconfig>
              <vsys>
                <entry name="vsys1">
                  <server-profile>
                    <saml-idp>
                      <entry name="okta-idp">
                        <validate-idp-certificate>yes</validate-idp-certificate>
                      </entry>
                      <entry name="legacy-idp">
                        <validate-idp-certificate>no</validate-idp-certificate>
                      </entry>
                    </saml-idp>
                  </server-profile>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
      </result>
    </response>
    """
    system_xml = """
    <response status="success">
      <result>
        <system>
          <ip-address>192.168.1.254</ip-address>
          <netmask>255.255.255.0</netmask>
          <default-gateway>192.168.1.1</default-gateway>
        </system>
      </result>
    </response>
    """

    def mock_op(cmd):
        if "running" in cmd:
            return (200, config_xml)
        elif "system" in cmd:
            return (200, system_xml)
        return (400, "<response status='error'></response>")

    mock_client.execute_op.side_effect = mock_op

    cartographer = Cartographer()
    graph_json = cartographer.build_graph()
    data = json.loads(graph_json)

    posture = data["metadata"]["posture"]
    assert "192.168.1.50/32" in posture["mgmt_permitted_ips"]
    assert "192.168.1.20/32" in posture["mgmt_permitted_ips"]
    assert posture["saml_idp_validate_cert"]["okta-idp"] == "yes"
    assert posture["saml_idp_validate_cert"]["legacy-idp"] == "no"

    nodes_by_id = {n["id"]: n for n in data["nodes"]}
    assert "interface_mgmt" in nodes_by_id
    assert "192.168.1.50/32" in nodes_by_id["interface_mgmt"]["permitted_ips"]



