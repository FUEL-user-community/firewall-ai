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
