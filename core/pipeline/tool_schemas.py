"""
Pydantic Argument Schemas for High-Risk Tools

Validates tool argument VALUES before execution, not just names.
Tools without a schema in TOOL_SCHEMAS fall through to existing tool executor validation.
"""

from pydantic import BaseModel, field_validator
from typing import Optional
import re
import ipaddress


class TestSecurityPolicyArgs(BaseModel):
    __test__ = False
    source: str
    destination: str
    port: str
    protocol: str = "6"

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        if v in ("any", ""):
            return v
        # Delegate IP/CIDR validation to the standard library
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
        # Allow FQDN (letters, digits, dots, hyphens)
        fqdn_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+$'
        if re.match(fqdn_pattern, v):
            return v
        raise ValueError(f"'{v}' is not a valid IP address, CIDR, FQDN, or 'any'")


class TestNatPolicyArgs(BaseModel):
    source: str
    destination: str
    port: str
    protocol: str = "6"

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        if v in ("any", ""):
            return v
        # Delegate IP/CIDR validation to the standard library
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
        fqdn_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+$'
        if re.match(fqdn_pattern, v):
            return v
        raise ValueError(f"'{v}' is not a valid IP address, CIDR, FQDN, or 'any'")


class GetLiveConfigArgs(BaseModel):
    xpath: str

    @field_validator('xpath')
    @classmethod
    def validate_xpath(cls, v):
        if not v.startswith("/"):
            raise ValueError(f"xpath must start with '/', got: '{v}'")
        return v


class ExecuteLogQueryArgs(BaseModel):
    log_type: str
    filter_query: Optional[str] = None

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

    def model_dump(self, *args, **kwargs):
        """Ensure canonical 'cmd' argument is always supplied to execute_operational_command (H2)."""
        data = super().model_dump(*args, **kwargs)
        effective_cmd = data.get("cmd") or data.get("command")
        if not effective_cmd:
            raise ValueError("Operational command ('cmd' or 'command') is required.")
        return {
            "cmd": effective_cmd.strip(),
            "target_device": data.get("target_device")
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
        try:
            ipaddress.ip_network(clean, strict=False)
            return clean
        except ValueError:
            pass
        fqdn_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+$'
        if re.match(fqdn_pattern, clean):
            return clean
        raise ValueError(f"'{v}' is not a valid IP address, CIDR, or FQDN")


# Registry: tool function name → schema class
# Tools not in this registry use existing tool executor validation.
TOOL_SCHEMAS = {
    "test_security_policy": TestSecurityPolicyArgs,
    "test_nat_policy": TestNatPolicyArgs,
    "test_routing_fib": TestRoutingFibArgs,
    "get_live_config": GetLiveConfigArgs,
    "execute_log_query": ExecuteLogQueryArgs,
    "execute_operational_command": ExecuteOperationalCommandArgs,
}

