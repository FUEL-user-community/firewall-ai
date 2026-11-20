"""
Pydantic Argument Schemas for High-Risk Tools

Validates tool argument VALUES before execution, not just names.
Tools without a schema in TOOL_SCHEMAS fall through to existing tool executor validation.
"""

from pydantic import BaseModel, field_validator
from typing import Optional
import re
import ipaddress


_FQDN_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+$')
_PREFIX_RE = re.compile(r'^[^/]+/\d{1,3}$')


def _validate_address(v: str, *, allow_cidr: bool, allow_any: bool = True) -> str:
    """
    Single source of truth for address arguments.

    - Host: must parse with ipaddress.ip_address (exactly one address).
    - CIDR (only if allow_cidr): prefix-length form only (a.b.c.d/nn). Dotted masks are
      rejected: ipaddress reads /255.255.255.0 as a netmask but /0.0.0.255 as a hostmask,
      so the same-looking input silently means different networks.
    - FQDN and 'any' remain accepted for backward compatibility.
    """
    if allow_any and v in ("any", ""):
        return v
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if allow_cidr and _PREFIX_RE.match(v):
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
    # All-numeric dotted strings that failed ip_address (e.g. 10.0.0.256, 999.1.1.1) are
    # malformed IPs, not hostnames; previously they slipped through the FQDN fallback.
    if "/" not in v and _FQDN_RE.match(v) and not re.fullmatch(r'[\d.]+', v):
        return v
    kind = "IP address, CIDR (a.b.c.d/nn), FQDN" if allow_cidr else "single IP address, FQDN"
    suffix = " or 'any'" if allow_any else ""
    raise ValueError(f"'{v}' is not a valid {kind}{suffix}")


class TestSecurityPolicyArgs(BaseModel):
    __test__ = False
    source: str
    destination: str
    port: str
    protocol: str = "6"
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    application: Optional[str] = None
    target_device: Optional[str] = None

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        # Policy match tests a single flow: host address required.
        return _validate_address(v, allow_cidr=False)


class TestNatPolicyArgs(BaseModel):
    source: str
    destination: str
    port: str
    protocol: str = "6"
    from_zone: Optional[str] = None
    to_interface: Optional[str] = None
    target_device: Optional[str] = None

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        return _validate_address(v, allow_cidr=False)


class TestPacketWalkArgs(BaseModel):
    __test__ = False
    source: str
    destination: str
    port: str = "443"
    protocol: str = "6"
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    application: Optional[str] = None
    virtual_router: Optional[str] = "default"
    target_device: Optional[str] = None

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        return _validate_address(v, allow_cidr=False)


class GetLiveConfigArgs(BaseModel):
    xpath: str
    target_device: Optional[str] = None

    @field_validator('xpath')
    @classmethod
    def validate_xpath(cls, v):
        if not v.startswith("/"):
            raise ValueError(f"xpath must start with '/', got: '{v}'")
        return v


class ExecuteLogQueryArgs(BaseModel):
    log_type: str
    filter_query: Optional[str] = None
    target_device: Optional[str] = None

    @field_validator('log_type')
    @classmethod
    def validate_log_type(cls, v):
        valid = {"traffic", "threat", "system", "config", "url", "wildfire", "data", "hipmatch"}
        if v.lower() not in valid:
            raise ValueError(f"'{v}' not in valid log types: {valid}")
        return v.lower()


class ExecuteOperationalCommandArgs(BaseModel):
    cmd: Optional[str] = None
    command: Optional[str] = None
    target_device: Optional[str] = None
    hitl_approved: Optional[bool] = False

    def model_dump(self, *args, **kwargs):
        """Ensure canonical 'cmd' argument is always supplied to execute_operational_command (H2)."""
        data = super().model_dump(*args, **kwargs)
        effective_cmd = data.get("cmd") or data.get("command")
        if not effective_cmd:
            raise ValueError("Operational command ('cmd' or 'command') is required.")
        return {
            "cmd": effective_cmd.strip(),
            "target_device": data.get("target_device"),
            "hitl_approved": data.get("hitl_approved", False)
        }


class TestRoutingFibArgs(BaseModel):
    ip: str
    virtual_router: Optional[str] = "default"
    target_device: Optional[str] = None

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v):
        clean = v.strip() if v else ""
        if not clean:
            raise ValueError("IP address cannot be empty.")
        # FIB lookup keeps CIDR support (prefix-length form only).
        return _validate_address(clean, allow_cidr=True, allow_any=False)


class TestPbfPolicyArgs(BaseModel):
    source: str
    destination: str
    destination_port: Optional[str] = "443"
    protocol: Optional[str] = "6"
    from_zone: Optional[str] = None
    application: Optional[str] = None
    target_device: Optional[str] = None

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        return _validate_address(v, allow_cidr=False)


class GetTelemetrySnapshotArgs(BaseModel):
    target_device: Optional[str] = None


class BoardOpsArgs(BaseModel):
    action: str
    thread_id: str = ""
    move_type: str = ""
    slug: str = "note"
    summary: str = ""
    target_files: str = ""
    unified_diff: str = ""
    limit: int = 15
    target_device: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        valid = {"sync", "post", "dispatch_spark"}
        clean = (v or "").strip().lower()
        if clean not in valid:
            raise ValueError(f"'{v}' not in valid board_ops actions: {sorted(valid)}")
        return clean


class SlotForgeArgs(BaseModel):
    action: str
    target_path: str = ""
    content: str = ""
    unified_diff: str = ""
    reason: str = "Autonomous slot hardening"
    target_device: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        valid = {"status", "init", "stage_diff", "stage_file", "verify_and_promote", "reset_inactive"}
        clean = (v or "").strip().lower()
        if clean not in valid:
            raise ValueError(f"'{v}' not in valid slot_forge actions: {sorted(valid)}")
        return clean


# Registry: tool function name → schema class
# Tools not in this registry use existing tool executor validation.
TOOL_SCHEMAS = {
    "test_security_policy": TestSecurityPolicyArgs,
    "test_nat_policy": TestNatPolicyArgs,
    "test_packet_walk": TestPacketWalkArgs,
    "test_routing_fib": TestRoutingFibArgs,
    "test_pbf_policy": TestPbfPolicyArgs,
    "get_telemetry_snapshot": GetTelemetrySnapshotArgs,
    "get_live_config": GetLiveConfigArgs,
    "execute_log_query": ExecuteLogQueryArgs,
    "execute_operational_command": ExecuteOperationalCommandArgs,
    "board_ops": BoardOpsArgs,
    "slot_forge": SlotForgeArgs,
}
