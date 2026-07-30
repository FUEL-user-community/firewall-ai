import os
import sys
import yaml
import logging
from core.panos.ops import execute_operational_command

logger = logging.getLogger(__name__)

def summon_toolkit(tray: str):
    """
    Pivot the investigation to a specific tool tray.
    
    Args:
        tray (str): The ID of the tray to summon (e.g., '#net', '#sec', '#sys', '#vpn').
    """
    return f"System: Pivoting to {tray} Toolkit..."

class ToolKeeper:
    """
    Tool registry and dynamic loader for the agentic pipeline.
    Manages loading specialized 'Trays' of tools while maintaining the '#core' anchor.
    """
    
    def __init__(self):
        # The registry path should prioritize the project-wide config/ directory
        self.registry_path = self._resolve_path()
        self.commands = self._load_yaml()
        
    def _resolve_path(self):
        """Resolves the path to commands.yaml, prioritizing the project config/ directory."""
        _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_path = os.path.join(_root, 'config', 'commands.yaml')
        core_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commands.yaml')
        
        if os.path.exists(config_path):
            return config_path
        return core_path

    def _load_yaml(self):
        if not os.path.exists(self.registry_path):
            logger.error(f"[TOOLS] Registry not found: {self.registry_path}")
            return {}
        try:
            with open(self.registry_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"[TOOLS] YAML Load Error: {e}")
            return {}

    def _create_function(self, tool_id, details):
        """Factory that converts YAML definition to a Python Closure."""
        cmd = details.get('cmd')
        cmd_list = details.get('commands')
        desc = details.get('description')
        
        def _sanitize_kwargs(kw):
            clean = {}
            for k, v in kw.items():
                val_str = str(v)
                # Reject dangerous shell/XML characters
                if any(c in val_str for c in '<>|&;`\'"$\\{}'):
                    raise ValueError(f"Invalid characters detected in argument '{k}'")
                clean[k] = val_str
            return clean

        # MACRO (List of Commands)
        if cmd_list and isinstance(cmd_list, list):
            def macro_func(target_device=None, frozen_list=cmd_list, **kwargs):
                results = []
                try:
                    safe_kwargs = _sanitize_kwargs(kwargs)
                except ValueError as ve:
                    return f"Input Validation Error: {ve}"
                    
                for c in frozen_list:
                    try:
                        final_c = c.format(**safe_kwargs)
                        out = execute_operational_command(final_c, target_device=target_device)
                        results.append(f"--- CMD: {final_c} ---\n{out}")
                    except Exception as e:
                        results.append(f"--- CMD: {c} (FAILED) ---\nError: {e}")
                return "\n".join(results)
            
            macro_func.__name__ = tool_id
            macro_func.__doc__ = desc
            return macro_func

        # SINGLE COMMAND
        elif cmd:
            def tool_func(target_device=None, **kwargs):
                try:
                    safe_kwargs = _sanitize_kwargs(kwargs)
                    final_cmd = cmd.format(**safe_kwargs)
                    return execute_operational_command(final_cmd, target_device=target_device)
                except ValueError as ve:
                    return f"Input Validation Error: {ve}"
                except Exception as e:
                    return f"Error: {e}"
            
        return None

    def get_tools(self, active_tray="#core"):
        """
        Fetches the toolset for the requested tray + implicit #core anchor.
        
        Args:
            active_tray (str): The tag to load (e.g. '#net').
        
        Returns:
            list[callable]: List of pure Python functions ready for Gemini.
        """
        tools = []
        
        # Rule 1: Always include the Pivot Tool (summon_toolkit)
        tools.append(summon_toolkit)
        
        # Rule 2: Include Native Python Tools
        try:
            from core.panos.research import search_live_docs
            tools.append(search_live_docs)
        except Exception as e:
            logger.debug(f"[TOOLS] Live research not available: {e}")
        
        # Rule 3: Security Policy Math
        try:
            from core.panos.ops import test_security_policy, test_nat_policy
            tools.append(test_security_policy)
            tools.append(test_nat_policy)
        except Exception as e:
            logger.warning(f"[TOOLS] Policy Math Init Error: {e}")

        # Rule 4: Fleet Inventory
        try:
            from core.panos.ops import get_device_inventory
            tools.append(get_device_inventory)
        except Exception as e:
            logger.warning(f"[TOOLS] Device Inventory Init Error: {e}")

        # Rule 5: Config Inspection & Log Forensics
        try:
            from core.panos.config import get_live_config
            from core.panos.logs import execute_log_query
            tools.append(get_live_config)
            tools.append(execute_log_query)
        except Exception as e:
            logger.warning(f"[TOOLS] Config/Log Tools Init Error: {e}")

        # Rule 6: Google Drive Knowledge Base
        try:
            from core.integrations.drive_knowledge import query_knowledge_base
            tools.append(query_knowledge_base)
            logger.info("[TOOLS] Google Drive Knowledge Base tool registered.")
        except Exception as e:
            logger.warning(f"[TOOLS] Drive Knowledge Base Init Error: {e}")


        # Rule 3: Scan YAML Registry
        for tool_id, details in self.commands.items():
            if not isinstance(details, dict): continue
            
            tags = details.get('tags', [])
            
            # Load if tag matches OR tool is #core
            if active_tray in tags or "#core" in tags:
                func = self._create_function(tool_id, details)
                if func:
                    tools.append(func)
                    
        # Verification Log
        logger.info(f"[TOOLS] Loaded Tray '{active_tray}': {len(tools)} tools.")
        return tools

