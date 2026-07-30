"""
PAN-OS API Client — Connection Pool Architecture
Manages connections to multiple firewalls via a device registry (config/devices.yaml).

The pool is lazy-loaded: connections are established on first use per device.
A default device is designated for backward compatibility with single-firewall usage.

Credential flow:
    devices.yaml (IP + label) → get_secret(f"panos_api_key_{device_name}") → Firewall()
"""

import os
import yaml
import logging
import urllib3
import traceback
import xml.etree.ElementTree as _ET
import threading
from typing import Tuple, Optional, Dict

# Official Palo Alto Networks library
from panos.firewall import Firewall
from panos.errors import PanDeviceError

logger = logging.getLogger(__name__)

# SECURITY: Enable SSL Verification by default. 
# Only suppress warnings if the user explicitly opts out for a lab environment.
verify_ssl = os.getenv("PANOS_VERIFY_SSL", "true").lower() != "false"
if not verify_ssl:
    logger.warning(
        "[CLIENT] ⚠️  SSL verification DISABLED (PANOS_VERIFY_SSL=false). "
        "This is insecure — use only for lab environments with self-signed certs."
    )
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PanOSClient:
    """
    Connection wrapper for a single PAN-OS firewall.
    Created and managed by PanOSClientPool — do not instantiate directly.
    """

    def __init__(self, device_name: str, hostname: str, api_key: str, label: str = ""):
        self.device_name = device_name
        self.hostname = hostname
        self.label = label

        try:
            self.fw = Firewall(hostname=hostname, api_key=api_key)
            logger.info(f"[PanOSClient] Initialized: {device_name} ({label}) @ {hostname}")
        except Exception as e:
            logger.error(f"[PanOSClient] Failed to initialize {device_name}: {e}")
            raise

    def execute_op(self, cli_cmd: str, timeout: int = 15) -> Tuple[int, str]:
        """
        Execute operational command via XML API.

        Args:
            cli_cmd: CLI command string (auto-converted to XML by pan-os-python)
            timeout: Request timeout in seconds

        Returns:
            Tuple of (status_code, response_xml)
        """
        try:
            if cli_cmd.strip().startswith("<"):
                result_xml = self.fw.op(cli_cmd, cmd_xml=False, xml=True)
                logger.debug(f"[{self.device_name}] Executed XML: {cli_cmd[:50]}...")
            else:
                result_xml = self.fw.op(cli_cmd, xml=True)
                logger.debug(f"[{self.device_name}] Executed CLI: {cli_cmd}")

            # NORMALIZE: Decode all possible return types to plain Python str
            if isinstance(result_xml, bytes):
                result_xml = result_xml.decode('utf-8', errors='replace')
            elif hasattr(result_xml, 'tag'):
                result_xml = _ET.tostring(result_xml, encoding='unicode')
            elif not isinstance(result_xml, str):
                result_xml = str(result_xml)

            return 200, result_xml

        except PanDeviceError as e:
            logger.error(f"[{self.device_name}] PAN-OS error: {e}")
            return 400, f"<response status='error'><msg>{str(e)}</msg></response>"

        except Exception as e:
            logger.error(f"[{self.device_name}] Request failed: {e}\n{traceback.format_exc()}")
            return 500, f"<response status='error'><msg>{str(e)}</msg></response>"

    def execute_log(self, query: str, nlogs: int = 50, timeout: int = 30) -> Tuple[int, str]:
        """Execute log query via type=log API."""
        try:
            self.fw.xapi.log(log_type='traffic', nlogs=nlogs, skip=0, filter=query)
            result_xml = self.fw.xapi.xml_result()
            return 200, result_xml
        except Exception as e:
            logger.error(f"[{self.device_name}] Log query failed: {e}")
            return 500, f"<response status='error'><msg>{str(e)}</msg></response>"

    def execute_report(self, report_name: str, timeout: int = 20) -> Tuple[int, str]:
        """Execute report query via type=report API."""
        try:
            report_xml = f"<type><report><get-report><reportname>{report_name}</reportname></get-report></report></type>"
            self.fw.xapi.op(cmd=report_xml)
            result_xml = self.fw.xapi.xml_result()
            return 200, result_xml
        except Exception as e:
            logger.error(f"[{self.device_name}] Report query failed: {e}")
            return 500, f"<response status='error'><msg>{str(e)}</msg></response>"

    def execute_user_id(self, cmd_xml: str, timeout: int = 15) -> Tuple[int, str]:
        """Execute User-ID API command to register/unregister dynamic tags."""
        try:
            self.fw.xapi.user_id(cmd=cmd_xml)
            result_xml = self.fw.xapi.xml_result()
            
            if isinstance(result_xml, bytes):
                result_xml = result_xml.decode('utf-8', errors='replace')
            elif hasattr(result_xml, 'tag'):
                import xml.etree.ElementTree as _ET
                result_xml = _ET.tostring(result_xml, encoding='unicode')
            elif not isinstance(result_xml, str):
                result_xml = str(result_xml)

            return 200, result_xml
        except PanDeviceError as e:
            logger.error(f"[{self.device_name}] PAN-OS User-ID error: {e}")
            return 400, f"<response status='error'><msg>{str(e)}</msg></response>"
        except Exception as e:
            logger.error(f"[{self.device_name}] User-ID Request failed: {e}")
            return 500, f"<response status='error'><msg>{str(e)}</msg></response>"


class PanOSClientPool:
    """
    Connection pool managing multiple PAN-OS firewalls.

    Reads fleet configuration from config/devices.yaml.
    Connections are lazy-loaded — established on first use per device.
    Credentials fetched from the configured secrets backend.

    Usage:
        pool = PanOSClientPool.get_instance()
        client = pool.get_client("fw-hq")
        status, result = client.execute_op("show system info")

        # Or use the default device:
        client = pool.get_client()
    """

    _instance: Optional['PanOSClientPool'] = None
    _lock = threading.Lock()

    def __init__(self):
        self._connections: Dict[str, PanOSClient] = {}
        self._registry = self._load_registry()
        self._default_device = self._resolve_default()
        logger.info(
            f"[Pool] Registry loaded: {len(self._registry)} device(s), "
            f"default='{self._default_device}'"
        )

    @classmethod
    def get_instance(cls) -> 'PanOSClientPool':
        """Get or create the singleton pool instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    def _load_registry(self) -> dict:
        """Load device registry from config/devices.yaml."""
        paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))), 'config', 'devices.yaml'),
            os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), 'devices.yaml'),
        ]

        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f) or {}
                    devices = data.get('firewalls', {})
                    if not devices:
                        raise ValueError(f"No firewalls defined in {path}")
                    logger.info(f"[Pool] Loaded {len(devices)} device(s) from {path}")
                    return devices
                except Exception as e:
                    raise RuntimeError(f"Failed to load device registry: {e}")

        raise FileNotFoundError(
            "Device registry not found. Create config/devices.yaml with your firewall definitions."
        )

    def _resolve_default(self) -> str:
        """Find the default device from the registry."""
        for name, config in self._registry.items():
            if config.get('default', False):
                return name
        # If no default is marked, use the first device
        first = next(iter(self._registry))
        logger.warning(f"[Pool] No default device marked — using '{first}'")
        return first

    def get_client(self, device_name: str = None) -> PanOSClient:
        """
        Get a PanOSClient for the specified device. Lazy-loads the connection.

        Args:
            device_name: Device key from devices.yaml (e.g., 'fw-hq').
                         If None, uses the default device.

        Returns:
            PanOSClient connected to the specified firewall.

        Raises:
            ValueError: If the device is not in the registry.
        """
        if device_name is None:
            device_name = self._default_device

        if device_name in self._connections:
            return self._connections[device_name]

        if device_name not in self._registry:
            available = ', '.join(self._registry.keys())
            raise ValueError(
                f"Device '{device_name}' not found in registry. "
                f"Available devices: {available}"
            )

        # Lazy-load: create connection on first use
        config = self._registry[device_name]
        hostname = config.get('ip') or os.getenv("PANOS_HOSTNAME")
        label = config.get('label', device_name)

        if not hostname:
            raise ValueError(f"No IP address configured for device '{device_name}'")

        # Fetch API key from secrets backend
        from core.integrations.secrets import get_secret
        secret_key = f"panos_api_key_{device_name.replace('-', '_')}"
        try:
            api_key = get_secret(secret_key)
        except Exception as e:
            raise ValueError(
                f"Failed to load API key for '{device_name}' "
                f"(secret: '{secret_key}'): {e}"
            )

        client = PanOSClient(
            device_name=device_name,
            hostname=hostname,
            api_key=api_key,
            label=label,
        )
        self._connections[device_name] = client
        return client

    def get_device_names(self) -> list:
        """Return list of all registered device names."""
        return list(self._registry.keys())

    def get_device_info(self) -> list:
        """Return list of device metadata dicts (no credentials)."""
        devices = []
        for name, config in self._registry.items():
            devices.append({
                'name': name,
                'ip': config.get('ip', 'unknown'),
                'label': config.get('label', name),
                'default': config.get('default', False),
                'connected': name in self._connections,
            })
        return devices

    @property
    def default_device(self) -> str:
        """Return the name of the default device."""
        return self._default_device

    @classmethod
    def reset(cls) -> None:
        """Reset the pool — used for testing."""
        if cls._instance is not None:
            cls._instance._connections.clear()
        cls._instance = None
        logger.info("[Pool] Connection pool reset")
