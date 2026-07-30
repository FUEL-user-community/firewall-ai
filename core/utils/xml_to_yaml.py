#!/usr/bin/env python3
"""
ToxicXmlSanitizer - High-Fidelity XML→YAML Transformer
Strips PII, preserves forensic depth, optimizes for LLM consumption.
"""


import re
import hashlib
import hmac
import yaml
import os
from typing import Dict, Any, Union, List


try:
    from lxml import etree as ET

    HAS_LXML = True
except ImportError:
    import xml.etree.ElementTree as ET

    HAS_LXML = False


# Converts PAN-OS XML into lean, Argument-Optimized YAML,
# reducing token count by ~60-80% while preserving structural context.


class ToxicXmlSanitizer:
    """
    High-Fidelity XML→YAML Transformer.
    Converts PAN-OS XML responses into dimensionally dense YAML
    optimized for LLM consumption with PII stripping.
    """

    # Sensitive tags that get fully redacted
    SENSITIVE_TAGS = {
        'phash', 'psk', 'password', 'key', 'secret', 'auth-key',
        'bind-password', 'certificate-data', 'private-key', 'api-key',
        'passphrase', 'shared-key', 'community', 'encrypted-password', 
        'hash', 'bind-dn', 'access-key', 'secret-key', 'rsa-private-key'
    }

    # Tags that contain data we want to mask (IPs, serials, etc)
    # but keep structural integrity via hashing.
    MASK_PATTERNS = {
        'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'serial': re.compile(r'\b[0-9A-F]{12,}\b')
    }

    def __init__(self, seed: str = None):
        raw_seed = seed or os.getenv('SANITIZER_SEED')
        if not raw_seed:
            import secrets as _secrets
            raw_seed = _secrets.token_hex(16)
        self.seed = raw_seed.encode('utf-8')

    def _hash_value(self, text: str, prefix: str = "VAL") -> str:
        """Deterministic, irreversible HMAC masking."""
        h = hmac.new(self.seed, text.encode('utf-8'), hashlib.sha256)
        return f"{{{{{prefix}_{h.hexdigest()[:8]}}}}}"

    def _sanitize_text(self, text) -> str:
        """Applies mechanical masking to sensitive identifiers."""
        if not text:
            return text

        # lxml returns _ElementStringResult (bytes-compatible subclass)
        # which breaks re.sub() with string patterns. Force to plain Python str.
        if not isinstance(text, str):
            text = str(text)

        for prefix, pattern in self.MASK_PATTERNS.items():
            def replacer(match):
                return self._hash_value(match.group(0), prefix.upper())

            text = pattern.sub(replacer, text)

        return text

    def _parse_cdata_content(self, cdata_text: str):
        """Dispatcher for CDATA blocks - routes to appropriate parser based on content signature."""
        if not cdata_text or len(cdata_text.strip()) == 0:
            return cdata_text

        # Detect content type by signature
        if 'top -' in cdata_text or 'load average:' in cdata_text:
            return self._parse_top_output(cdata_text)
        elif 'Filesystem' in cdata_text and ('Mounted on' in cdata_text or 'IUse%' in cdata_text):
            return self._parse_df_output(cdata_text)
        else:
            # Fallback: return as-is for unknown formats
            return cdata_text

    def _parse_top_output(self, cdata_text: str) -> dict:
        """Parse 'top' command output from show system resources."""
        try:
            lines = cdata_text.strip().split('\n')
            result = {}

            for line in lines:
                line = line.strip()

                # Parse uptime and load averages
                if 'up' in line and 'load average:' in line:
                    if 'load average:' in line:
                        load_part = line.split('load average:')[1].strip()
                        load_values = [float(x.strip()) for x in load_part.split(',')[:3]]
                        result['load_average'] = load_values
                    if 'up' in line:
                        up_parts = line.split('up')[1].split(',')[0].strip()
                        result['uptime'] = up_parts

                # Parse CPU line
                elif '%Cpu' in line or 'Cpu(s)' in line:
                    if 'id' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if 'id' in part and i > 0:
                                try:
                                    result['cpu_idle_pct'] = float(parts[i - 1])
                                except:
                                    pass

                # Parse memory line
                elif 'KiB Mem' in line or 'Mem:' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'total' in part and i > 0:
                            try:
                                result['memory_total_kb'] = int(parts[i - 1])
                            except:
                                pass
                        if 'used' in part and i > 0 and 'memory_used_kb' not in result:
                            try:
                                result['memory_used_kb'] = int(parts[i - 1])
                            except:
                                pass

                # Parse process counts
                elif 'Tasks:' in line or 'total' in line:
                    if 'zombie' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if 'zombie' in part and i > 0:
                                try:
                                    result['zombie_processes'] = int(parts[i - 1])
                                except:
                                    pass

            # Calculate memory usage percentage
            if 'memory_total_kb' in result and 'memory_used_kb' in result:
                total = result['memory_total_kb']
                used = result['memory_used_kb']
                if total > 0:
                    result['memory_used_pct'] = round((used / total) * 100, 1)

            return result if result else cdata_text
        except Exception:
            return cdata_text

    def _parse_df_output(self, cdata_text: str) -> dict:
        """Parse 'df' command output from show system disk-space."""
        try:
            lines = cdata_text.strip().split('\n')
            filesystems = []

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        fs_info = {
                            'filesystem': parts[0],
                            'usage_pct': parts[-2].replace('%', ''),
                            'mounted_on': parts[-1]
                        }
                        filesystems.append(fs_info)
                    except:
                        pass

            return {'filesystems': filesystems} if filesystems else cdata_text
        except Exception:
            return cdata_text

    def _xml_to_dict(self, element: ET.Element) -> Union[Dict, str, List]:
        """
        Recursive XML tree traversal with semantic normalization.
        Handles PAN-OS member collections, sensitive tag redaction,
        and identity resolution.
        """
        # 1. Security: Redact if in sensitive list
        tag_lower = element.tag.lower()
        if tag_lower in self.SENSITIVE_TAGS:
            return "{{REDACTED_SECRET}}"

        # 2. Identity Resolution: Capture Object Identity
        obj_name = element.get('name')

        # 3. Collection Normalization: Handle <member> tags
        # PAN-OS uses <member> for arrays. Squash into clean YAML lists.
        children = list(element)
        if all(c.tag == 'member' for c in children) and children:
            members = []
            for m in children:
                m_data = self._xml_to_dict(m)
                if m_data is not None:
                    members.append(m_data)
            return members

        # 4. Leaf Node Processing
        # Force to plain str — lxml returns _ElementStringResult for CDATA
        # which is a bytes-compatible type that breaks re.sub() in _sanitize_text.
        text_content = str(element.text or "").strip()
        if not children:
            if text_content:
                sanitized = self._sanitize_text(text_content)
                return sanitized
            return obj_name if obj_name else ""

        # 5. Branch Node Processing
        result = {}
        if obj_name:
            result['@name'] = obj_name

        text_content = str(element.text or "").strip()
        if text_content:
            result['#text'] = self._sanitize_text(text_content)

        for child in children:
            child_data = self._xml_to_dict(child)

            # Handle duplicate tags as lists
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data

        return result

    def convert_string(self, raw_xml, return_stats: bool = False):
        """
        Transforms an XML string into high-fidelity YAML on-the-fly.
        Automatically handles multiple roots by wrapping them in a <root> tag.

        Args:
            raw_xml: Raw XML string or bytes to convert
            return_stats: If True, returns (yaml_output, stats_dict)

        Returns:
            str if return_stats=False, else tuple(str, dict)
        """
        if not raw_xml:
            return ""

        # Defensive: normalize bytes → str before any processing
        if isinstance(raw_xml, bytes):
            raw_xml = raw_xml.decode('utf-8', errors='replace')

        try:
            try:
                root = ET.fromstring(raw_xml.encode('utf-8'))
            except Exception as e:
                if "junk after document element" in str(e):
                    # Multi-root safety: Wrap in a virtual root
                    wrapped = f"<root>\n{raw_xml}\n</root>"
                    root = ET.fromstring(wrapped.encode('utf-8'))
                else:
                    raise

            clean_dict = {root.tag: self._xml_to_dict(root)}

            yaml_output = yaml.dump(
                clean_dict,
                sort_keys=False,
                default_flow_style=False,
                width=120,
                allow_unicode=True
            )

            if return_stats:
                xml_bytes = len(raw_xml.encode('utf-8'))
                yaml_bytes = len(yaml_output.encode('utf-8'))
                reduction_pct = ((xml_bytes - yaml_bytes) / xml_bytes * 100) if xml_bytes > 0 else 0

                cdata_parsed = 'load_average' in yaml_output or 'filesystems' in yaml_output
                parser_type = None
                if 'load_average' in yaml_output:
                    parser_type = 'top'
                elif 'filesystems' in yaml_output:
                    parser_type = 'df'

                stats = {
                    'xml_bytes': xml_bytes,
                    'yaml_bytes': yaml_bytes,
                    'reduction_pct': round(reduction_pct, 1),
                    'cdata_parsed': cdata_parsed,
                    'parser_type': parser_type
                }
                return yaml_output, stats

            return yaml_output
        except Exception as e:
            return f"CRITICAL: Telemetry Transformation Error - {e}"

    def convert_file(self, xml_path: str, yaml_out_path: str = None) -> str:
        """
        Converts an XML file to YAML on disk.
        Returns a stats summary string.
        """
        if not os.path.exists(xml_path):
            raise FileNotFoundError(f"Telemetry source not found: {xml_path}")

        with open(xml_path, 'r', encoding='utf-8') as f:
            raw_xml = f.read()

        xml_size = len(raw_xml)

        try:
            root = ET.fromstring(raw_xml.encode('utf-8'))
        except Exception as e:
            return f"CRITICAL: Telemetry Deserialization Failed - {e}"

        clean_dict = {root.tag: self._xml_to_dict(root)}

        yaml_output = yaml.dump(
            clean_dict,
            sort_keys=False,
            default_flow_style=False,
            width=120,
            allow_unicode=True
        )

        if yaml_out_path:
            with open(yaml_out_path, 'w', encoding='utf-8') as f:
                f.write(yaml_output)

        yaml_size = len(yaml_output)
        reduction = ((xml_size - yaml_size) / xml_size) * 100

        engine_type = "lxml" if HAS_LXML else "ElementTree"

        stats = (
            f"--- Conversion Report ---\n"
            f"Engine:      {engine_type}\n"
            f"Input Size:  {xml_size} bytes\n"
            f"Output Size: {yaml_size} bytes\n"
            f"Reduction:   {reduction:.1f}%"
        )
        return stats


def main():
    if len(sys.argv) < 2:
        print("Usage: python xml_to_yaml.py <input.xml> [output.yaml]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.xml', '.yaml')

    sanitizer = ToxicXmlSanitizer()
    print(f"Transforming: {input_file}...")
    stats = sanitizer.convert_file(input_file, output_file)
    print(stats)
    print(f"Output: {output_file}")


if __name__ == "__main__":
    main()
