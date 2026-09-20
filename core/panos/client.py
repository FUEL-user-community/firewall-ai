"""
PAN-OS API Client — Connection Pool Architecture
Manages connections to multiple firewalls via a device registry (config/devices.yaml).

The pool is lazy-loaded: connections are established on first use per device.
A default device is designated for backward compatibility with single-firewall usage.

Credential flow:
    devices.yaml (IP + label) → get_secret(f"panos_api_key_{device_name}") → Firewall()
"""

import os
import ssl
import yaml
import logging
import urllib3
import xml.etree.ElementTree as _ET
from xml.sax.saxutils import escape
import threading
from pathlib import Path
from typing import Tuple, Optional, Dict, List, Any

# Official Palo Alto Networks library
from panos.firewall import Firewall
from panos.errors import PanDeviceError

__all__ = ["PanOSClient", "PanOSClientPool"]

logger = logging.getLogger(__name__)

# Base path definitions
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_DEFAULT_REGISTRY_PATH = _BASE_DIR / "config" / "devices.yaml"
_FALLBACK_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "devices.yaml"

# SECURITY: Enable SSL Verification by default (C2).
# Supports both PANOS_VERIFY_SSL and PANOS_SSL_VERIFY environment flags.
_env_ssl = os.getenv("PANOS_VERIFY_SSL", os.getenv("PANOS_SSL_VERIFY", "true")).lower()
VERIFY_SSL: bool = _env_ssl not in ("false", "0", "no", "off")

if not VERIFY_SSL:
    logger.warning(
        "[CLIENT] ⚠️  SSL verification DISABLED (PANOS_VERIFY_SSL=false). "
        "This is insecure — use only for lab environments with self-signed certs."
    )
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _format_error_xml(msg: Any) -> str:
    """Format an XML error response safely escaping entity characters (H1)."""
    clean_msg = (
        escape(str(msg), entities={'"': "&quot;", "'": "&apos;"})
        if msg is not None
        else "Unknown error"
    )
    return f"<response status='error'><msg>{clean_msg}</msg></response>"


def _normalize_xml_response(result_xml: Any) -> str:
    """Normalize XML result from pan-os-python to a clean Python string (Self-Audit 2)."""
    if result_xml is None:
        return ""
    if isinstance(result_xml, bytes):
        return result_xml.decode('utf-8', errors='replace')
    if hasattr(result_xml, 'tag'):
        return _ET.tostring(result_xml, encoding='unicode')
    if isinstance(result_xml, str):
        return result_xml
    return str(result_xml)


class PanOSClient:
    """
    Connection wrapper for a single PAN-OS firewall.
    Created and managed by PanOSClientPool — do not instantiate directly.
    """

    def __init__(
        self,
        device_name: str,
        hostname: str,
        api_key: str,
        label: str = "",
        verify_ssl: Optional[bool] = None
    ):
        self.device_name = device_name
        self.hostname = hostname
        self.label = label
        self.verify_ssl = VERIFY_SSL if verify_ssl is None else verify_ssl

        try:
            self.fw = Firewall(hostname=hostname, api_key=api_key)
            self._configure_ssl()
            logger.info(f"[PanOSClient] Initialized: {device_name} ({label}) @ {hostname} (ssl_verify={self.verify_ssl})")
        except Exception as e:
            logger.error(f"[PanOSClient] Failed to initialize {device_name}: {e}")
            raise

    def _configure_ssl(self):
        """Configure SSL context on underlying pan.xapi instance (C2)."""
        if not hasattr(self.fw, 'xapi') or self.fw.xapi is None:
            return

        if self.verify_ssl:
            try:
                cert_path = os.getenv("PANOS_SSL_CERT_PATH")
                if cert_path and os.path.exists(cert_path):
                    self.fw.xapi.ssl_context = ssl.create_default_context(cafile=cert_path)
                else:
                    self.fw.xapi.ssl_context = ssl.create_default_context()
            except Exception as e:
                logger.warning(f"[PanOSClient] Failed to initialize verified SSL context for {self.device_name}: {e}")
        else:
            try:
                self.fw.xapi.ssl_context = ssl._create_unverified_context()
            except Exception as e:
                logger.debug(f"[PanOSClient] Unverified context setup: {e}")

    def _apply_timeout(self, timeout: Optional[int]):
        """Apply timeout in seconds to both Firewall and xapi wrappers (H4)."""
        if timeout and timeout > 0:
            try:
                self.fw.timeout = timeout
                if hasattr(self.fw, 'xapi') and self.fw.xapi is not None:
                    self.fw.xapi.timeout = timeout
            except Exception as e:
                logger.debug(f"[PanOSClient] Could not set timeout on client: {e}")

    def close(self):
        """Cleanly release client resources and cached connections (M2)."""
        try:
            if hasattr(self, 'fw') and hasattr(self.fw, '_xapi_private'):
                self.fw._xapi_private = None
        except Exception as e:
            logger.debug(f"[PanOSClient] Error during close: {e}")

    def execute_op(self, cli_cmd: str, timeout: int = 15) -> Tuple[int, str]:
        """
        Execute operational command via XML API.

        Args:
            cli_cmd: CLI command string (auto-converted to XML by pan-os-python)
            timeout: Request timeout in seconds

        Returns:
            Tuple of (status_code, response_xml)
        """
        if not cli_cmd or not isinstance(cli_cmd, str):
            return 400, _format_error_xml("Empty or invalid CLI command provided")

        self._apply_timeout(timeout)

        try:
            if cli_cmd.strip().startswith("<"):
                result_xml = self.fw.op(cli_cmd, cmd_xml=False, xml=True)
                logger.debug(f"[{self.device_name}] Executed XML: {cli_cmd[:50]}...")
            else:
                result_xml = self.fw.op(cli_cmd, xml=True)
                logger.debug(f"[{self.device_name}] Executed CLI: {cli_cmd}")

            normalized = _normalize_xml_response(result_xml)
            return 200, normalized

        except PanDeviceError as e:
            logger.error(f"[{self.device_name}] PAN-OS error: {e}")
            return 400, _format_error_xml(e)

        except Exception as e:
            logger.error(f"[{self.device_name}] Request failed: {e}", exc_info=True)
            return 500, _format_error_xml(e)

    def execute_log(self, log_type: str = 'traffic', query: str = "", nlogs: int = 50, timeout: int = 30) -> Tuple[int, str]:
        """
        Execute log query via native pan-os-python type=log API with async job polling.
        
        Args:
            log_type: 'traffic', 'threat', 'system', or 'config'
            query: PAN-OS log filter expression
            nlogs: Number of logs to retrieve
            timeout: Timeout in seconds for async job completion
        """
        self._apply_timeout(timeout)
        try:
            clean_log_type = (log_type or 'traffic').strip().lower()
            self.fw.xapi.log(log_type=clean_log_type, nlogs=nlogs, skip=0, filter=query or "", timeout=timeout)
            result_xml = self.fw.xapi.xml_result()
            normalized = _normalize_xml_response(result_xml)
            return 200, normalized
        except Exception as e:
            logger.error(f"[{self.device_name}] Log query failed ({log_type}): {e}", exc_info=True)
            return 500, _format_error_xml(e)

    def execute_report(self, report_name: str, report_type: str = 'predefined', timeout: int = 20) -> Tuple[int, str]:
        """
        Execute report query via native pan-os-python type=report API (H2).
        
        Args:
            report_name: Name of predefined or custom report
            report_type: 'predefined' (default) or 'custom'
            timeout: Timeout in seconds for report generation
        """
        if not report_name or not isinstance(report_name, str) or not report_name.strip():
            return 400, _format_error_xml("Invalid or empty report name provided")

        self._apply_timeout(timeout)
        try:
            clean_name = report_name.strip()
            clean_type = (report_type or 'predefined').strip().lower()
            self.fw.xapi.report(reporttype=clean_type, reportname=clean_name, timeout=timeout)
            result_xml = self.fw.xapi.xml_result()
            normalized = _normalize_xml_response(result_xml)
            return 200, normalized
        except Exception as e:
            logger.error(f"[{self.device_name}] Report query failed ({report_name}): {e}", exc_info=True)
            return 500, _format_error_xml(e)

    def execute_user_id(self, cmd_xml: str, timeout: int = 15) -> Tuple[int, str]:
        """Execute User-ID API command to register/unregister dynamic tags."""
        if not cmd_xml or not isinstance(cmd_xml, str):
            return 400, _format_error_xml("Empty or invalid User-ID XML command provided")

        self._apply_timeout(timeout)

        try:
            self.fw.xapi.user_id(cmd=cmd_xml)
            result_xml = self.fw.xapi.xml_result()
            normalized = _normalize_xml_response(result_xml)
            return 200, normalized

        except PanDeviceError as e:
            logger.error(f"[{self.device_name}] PAN-OS User-ID error: {e}")
            return 400, _format_error_xml(e)

        except Exception as e:
            logger.error(f"[{self.device_name}] User-ID Request failed: {e}", exc_info=True)
            return 500, _format_error_xml(e)


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

    def __init__(self, registry_path: Optional[Path] = None):
        self._connections: Dict[str, PanOSClient] = {}
        self._pool_lock = threading.Lock()
        self._registry_path = registry_path
        self._registry = self._load_registry()
        self._default_device = self._resolve_default()
        logger.info(
            f"[Pool] Registry loaded: {len(self._registry)} device(s), "
            f"default='{self._default_device}'"
        )

    @classmethod
    def get_instance(cls) -> 'PanOSClientPool':
        """Get or create the singleton pool instance using double-checked locking (H2)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _load_registry(self) -> dict:
        """Load device registry from config/devices.yaml using Path (M3)."""
        paths = []
        if self._registry_path:
            paths.append(Path(self._registry_path))
        paths.extend([_DEFAULT_REGISTRY_PATH, _FALLBACK_REGISTRY_PATH])

        for path in paths:
            if path.exists():
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
        Get a PanOSClient for the specified device. Lazy-loads the connection (H3).

        Args:
            device_name: Device key from devices.yaml (e.g., 'fw-hq').
                         If None, uses the default device.

        Returns:
            PanOSClient connected to the specified firewall.

        Raises:
            ValueError: If the device is not in the registry or secret is missing.
        """
        if device_name is None or (isinstance(device_name, str) and device_name.lower() == "default"):
            device_name = self._default_device

        # Fast path lock-free read
        if device_name in self._connections:
            return self._connections[device_name]

        with self._pool_lock:
            # Re-check under lock (double-checked pattern)
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

            # Fetch API key from secrets backend with normalized key and fallback (Self-Audit 1)
            from core.integrations.secrets import get_secret
            normalized_name = device_name.lower().replace('-', '_').replace('.', '_')
            secret_key = f"panos_api_key_{normalized_name}"
            
            api_key = None
            try:
                api_key = get_secret(secret_key)
            except Exception as e:
                logger.debug(f"[Pool] Secret lookup '{secret_key}' failed: {e}")

            # Fallback to PANOS_API_KEY environment variable for default device
            if not api_key and (device_name == self._default_device or len(self._registry) == 1):
                api_key = os.getenv("PANOS_API_KEY")

            if not api_key:
                raise ValueError(
                    f"Failed to load API key for '{device_name}' "
                    f"(tried secret '{secret_key}' and PANOS_API_KEY fallback)"
                )

            client = PanOSClient(
                device_name=device_name,
                hostname=hostname,
                api_key=api_key,
                label=label,
                verify_ssl=VERIFY_SSL
            )
            self._connections[device_name] = client
            return client

    def get_device_names(self) -> List[str]:
        """Return list of all registered device names."""
        return list(self._registry.keys())

    def get_device_info(self) -> List[Dict[str, Any]]:
        """Return list of device metadata dicts (no credentials)."""
        with self._pool_lock:
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
        """Reset the pool and close all managed client connections (M2)."""
        with cls._lock:
            if cls._instance is not None:
                with cls._instance._pool_lock:
                    for name, client in list(cls._instance._connections.items()):
                        try:
                            client.close()
                        except Exception as e:
                            logger.debug(f"[Pool] Error closing client '{name}': {e}")
                    cls._instance._connections.clear()
                cls._instance = None
        logger.info("[Pool] Connection pool reset")
