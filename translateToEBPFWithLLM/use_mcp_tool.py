"""MCP Tool utility for interfacing with the Gemini API."""

from pathlib import Path
from typing import Any, Dict, Optional, List
from dataclasses import dataclass

@dataclass
class MCPContent:
    type: str
    text: str

@dataclass
class MCPResult:
    content: List[MCPContent]
    is_error: bool = False

class MCPToolError(Exception):
    """Custom exception for MCP tool-related errors."""
    pass

def use_mcp_tool(server_name: str, tool_name: str, arguments: Dict[str, Any]) -> MCPResult:
    """
    Use an MCP tool with the specified parameters.
    
    Args:
        server_name: Name of the MCP server to use
        tool_name: Name of the tool to execute
        arguments: Dictionary of arguments to pass to the tool
        
    Returns:
        MCPResult: Result containing content from the tool execution
        
    Raises:
        MCPToolError: If there's an error during tool execution
    """
    if server_name != "gemini":
        raise MCPToolError(f"Unknown MCP server: {server_name}")
        
    if tool_name != "translate_iptables":
        raise MCPToolError(f"Unknown tool: {tool_name}")
        
    if not arguments.get("prompt"):
        raise MCPToolError("Prompt is required")
    
    # Import Gemini SDK here to avoid loading until needed
    import google.generativeai as genai
    
    try:
        # Get config file
        config_paths = [
            Path('~/.vscode-insiders/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json').expanduser(),
            Path('~/.vscode/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json').expanduser()
        ]
        
        config: Optional[dict] = None
        for path in config_paths:
            if path.exists():
                import json
                with open(path) as f:
                    config = json.load(f)
                    if config.get('gemini_api_key'):
                        break
                    
        if not config or not config.get('gemini_api_key'):
            raise MCPToolError("Gemini API key not found in MCP settings")
            
        # Configure Gemini
        genai.configure(api_key=config['gemini_api_key'])
        
        # Get model and generation config
        model = genai.GenerativeModel(
            arguments.get('model', 'gemini-pro'),
            generation_config=genai.types.GenerationConfig(
                temperature=float(arguments.get('temperature', 0.2))
            )
        )
        
        # Generate content
        response = model.generate_content(arguments['prompt'])
        
        if not response.text:
            raise MCPToolError("Empty response from Gemini API")
            
        return MCPResult(
            content=[MCPContent(type='text', text=response.text)]
        )
        
    except Exception as e:
        raise MCPToolError(f"Error using Gemini API: {str(e)}")
