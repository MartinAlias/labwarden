"""MCP server exposing LabWarden's read-only tools."""

from labwarden.mcp_server.server import build_server

__all__ = ["build_server"]
