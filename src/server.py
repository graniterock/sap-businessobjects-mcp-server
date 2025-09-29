#!/usr/bin/env python3
"""
SAP BusinessObjects MCP Server

A Model Context Protocol server for SAP BusinessObjects 4.3+ administration.
Provides tools for user permission management, email list administration,
and Crystal Reports diagnostics.
"""

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

from auth import SAPBOAuthenticator
from permissions import PermissionManager
from email_manager import EmailListManager
from diagnostics import DiagnosticsManager
from config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SAPBusinessObjectsMCPServer:
    """Main MCP server for SAP BusinessObjects administration."""

    def __init__(self):
        self.config = Config()
        self.authenticator = SAPBOAuthenticator(self.config)
        self.permission_manager = PermissionManager(self.config)
        self.email_manager = EmailListManager(self.config)
        self.diagnostics = DiagnosticsManager(self.config)
        self.server = Server("sap-businessobjects")

        # Register tools
        self._register_tools()

    def _register_tools(self):
        """Register all available MCP tools."""

        # User Permission Management Tools
        @self.server.list_tools()
        async def list_tools() -> ListToolsResult:
            return ListToolsResult(
                tools=[
                    Tool(
                        name="copy_user_permissions",
                        description="Copy all permissions from source user to target user(s)",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "source_user": {
                                    "type": "string",
                                    "description": "Username to copy permissions from"
                                },
                                "target_users": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "List of usernames to copy permissions to"
                                },
                                "include_groups": {
                                    "type": "boolean",
                                    "default": True,
                                    "description": "Whether to copy group memberships"
                                },
                                "dry_run": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "Preview changes without applying them"
                                }
                            },
                            "required": ["source_user", "target_users"]
                        }
                    ),
                    Tool(
                        name="manage_report_mailing_list",
                        description="Add or remove email addresses from recurring report instances",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "report_name": {
                                    "type": "string",
                                    "description": "Name of the report to modify"
                                },
                                "action": {
                                    "type": "string",
                                    "enum": ["add", "remove", "list"],
                                    "description": "Action to perform on the mailing list"
                                },
                                "email_addresses": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Email addresses to add or remove"
                                },
                                "dry_run": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "Preview changes without applying them"
                                }
                            },
                            "required": ["report_name", "action"]
                        }
                    ),
                    Tool(
                        name="diagnose_crystal_reports",
                        description="Run health checks and diagnostics on Crystal Reports",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "report_ids": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Specific report IDs to check (empty for all)"
                                },
                                "auto_fix": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "Automatically fix common issues"
                                },
                                "generate_report": {
                                    "type": "boolean",
                                    "default": True,
                                    "description": "Generate detailed diagnostic report"
                                }
                            }
                        }
                    ),
                    Tool(
                        name="list_user_permissions",
                        description="Get detailed permission information for a user",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "username": {
                                    "type": "string",
                                    "description": "Username to get permissions for"
                                },
                                "include_groups": {
                                    "type": "boolean",
                                    "default": True,
                                    "description": "Include group membership details"
                                }
                            },
                            "required": ["username"]
                        }
                    ),
                    Tool(
                        name="bulk_update_email_lists",
                        description="Update multiple report mailing lists at once",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "updates": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "report_name": {"type": "string"},
                                            "action": {"type": "string", "enum": ["add", "remove"]},
                                            "email_addresses": {
                                                "type": "array",
                                                "items": {"type": "string"}
                                            }
                                        },
                                        "required": ["report_name", "action", "email_addresses"]
                                    },
                                    "description": "List of email list updates to perform"
                                },
                                "dry_run": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "Preview changes without applying them"
                                }
                            },
                            "required": ["updates"]
                        }
                    )
                ]
            )

        @self.server.call_tool()
        async def call_tool(request: CallToolRequest) -> CallToolResult:
            """Handle tool execution requests."""
            try:
                # Ensure we're authenticated
                if not await self.authenticator.ensure_authenticated():
                    return CallToolResult(
                        content=[
                            TextContent(
                                type="text",
                                text="❌ Failed to authenticate with SAP BusinessObjects server"
                            )
                        ],
                        isError=True
                    )

                # Route to appropriate handler
                if request.name == "copy_user_permissions":
                    result = await self._handle_copy_permissions(request.arguments)
                elif request.name == "manage_report_mailing_list":
                    result = await self._handle_manage_email_list(request.arguments)
                elif request.name == "diagnose_crystal_reports":
                    result = await self._handle_diagnose_reports(request.arguments)
                elif request.name == "list_user_permissions":
                    result = await self._handle_list_permissions(request.arguments)
                elif request.name == "bulk_update_email_lists":
                    result = await self._handle_bulk_email_updates(request.arguments)
                else:
                    return CallToolResult(
                        content=[
                            TextContent(
                                type="text",
                                text=f"❌ Unknown tool: {request.name}"
                            )
                        ],
                        isError=True
                    )

                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=result
                        )
                    ]
                )

            except Exception as e:
                logger.error(f"Error executing tool {request.name}: {e}")
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=f"❌ Error executing {request.name}: {str(e)}"
                        )
                    ],
                    isError=True
                )

    async def _handle_copy_permissions(self, args: Dict[str, Any]) -> str:
        """Handle user permission copying."""
        source_user = args["source_user"]
        target_users = args["target_users"]
        include_groups = args.get("include_groups", True)
        dry_run = args.get("dry_run", False)

        return await self.permission_manager.copy_permissions(
            source_user, target_users, include_groups, dry_run
        )

    async def _handle_manage_email_list(self, args: Dict[str, Any]) -> str:
        """Handle email list management."""
        report_name = args["report_name"]
        action = args["action"]
        email_addresses = args.get("email_addresses", [])
        dry_run = args.get("dry_run", False)

        return await self.email_manager.manage_mailing_list(
            report_name, action, email_addresses, dry_run
        )

    async def _handle_diagnose_reports(self, args: Dict[str, Any]) -> str:
        """Handle Crystal Reports diagnostics."""
        report_ids = args.get("report_ids", [])
        auto_fix = args.get("auto_fix", False)
        generate_report = args.get("generate_report", True)

        return await self.diagnostics.diagnose_reports(
            report_ids, auto_fix, generate_report
        )

    async def _handle_list_permissions(self, args: Dict[str, Any]) -> str:
        """Handle listing user permissions."""
        username = args["username"]
        include_groups = args.get("include_groups", True)

        return await self.permission_manager.list_user_permissions(
            username, include_groups
        )

    async def _handle_bulk_email_updates(self, args: Dict[str, Any]) -> str:
        """Handle bulk email list updates."""
        updates = args["updates"]
        dry_run = args.get("dry_run", False)

        return await self.email_manager.bulk_update_email_lists(updates, dry_run)

async def main():
    """Main entry point for the MCP server."""
    server_instance = SAPBusinessObjectsMCPServer()

    async with stdio_server() as (read_stream, write_stream):
        await server_instance.server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="sap-businessobjects",
                server_version="1.0.0",
                capabilities={}
            )
        )

if __name__ == "__main__":
    asyncio.run(main())