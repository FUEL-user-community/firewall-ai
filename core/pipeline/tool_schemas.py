"""
Pydantic Argument Schemas for High-Risk Tools

Validates tool argument VALUES before execution, not just names.
Tools without a schema in TOOL_SCHEMAS fall through to existing tool executor validation.
"""

from pydantic import BaseModel, field_validator
import re


class TestSecurityPolicyArgs(BaseModel):
    source: str
    destination: str
    port: str
    protocol: str = "6"

    @field_validator('source', 'destination')
    @classmethod
    def validate_ip_or_any(cls, v):
        import ipaddress
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
        import ipaddress
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
    filter_query: str = None

    @field_validator('log_type')
    @classmethod
    def validate_log_type(cls, v):
        valid = {"traffic", "threat", "system", "config", "url", "wildfire", "data", "hipmatch"}
        if v.lower() not in valid:
            raise ValueError(f"'{v}' not in valid log types: {valid}")
        return v.lower()


class ExecuteOperationalCommandArgs(BaseModel):
    command: str
    target_device: str = None


# Registry: tool function name → schema class
# Tools not in this registry use existing tool executor validation.
TOOL_SCHEMAS = {
    "test_security_policy": TestSecurityPolicyArgs,
    "test_nat_policy": TestNatPolicyArgs,
    "get_live_config": GetLiveConfigArgs,
    "execute_log_query": ExecuteLogQueryArgs,
    "execute_operational_command": ExecuteOperationalCommandArgs,
}
