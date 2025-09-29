#!/usr/bin/env python3
"""
SAP BusinessObjects FastMCP Server

A FastMCP-powered server for SAP BusinessObjects 4.3+ administration.
Provides enterprise-grade tools for user permission management, email list administration,
and Crystal Reports diagnostics with authentication and session management.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from fastmcp import FastMCP, Context
from fastmcp.server.auth import GoogleProvider, Auth0Provider
from fastmcp.utilities import ToolError

from auth import SAPBOAuthenticator
from permissions import PermissionManager
from email_manager import EmailListManager
from diagnostics import DiagnosticsManager
from config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SAPBusinessObjectsFastMCPServer:
    """FastMCP-powered SAP BusinessObjects administration server."""

    def __init__(self, enable_auth: bool = False):
        """Initialize the FastMCP server with optional authentication."""
        self.config = Config.from_file() if hasattr(Config, 'from_file') else Config()

        # Initialize SAP BO components
        self.authenticator = SAPBOAuthenticator(self.config)
        self.permission_manager = PermissionManager(self.config)
        self.email_manager = EmailListManager(self.config)
        self.diagnostics = DiagnosticsManager(self.config)

        # Configure authentication if enabled
        auth_provider = None
        if enable_auth:
            # Configure Google OAuth for enterprise authentication
            # In production, these would come from environment variables
            auth_provider = GoogleProvider(
                client_id="your-google-client-id",
                client_secret="your-google-client-secret",
                base_url="https://your-server.com"
            )

        # Initialize FastMCP server
        self.mcp = FastMCP(
            name="sap-businessobjects-enterprise",
            version="2.0.0",
            description="Enterprise SAP BusinessObjects administration with FastMCP",
            auth=auth_provider,
            mask_error_details=True  # Security: mask internal errors in production
        )

        # Register all tools using decorators
        self._register_tools()

    def _register_tools(self):
        """Register all MCP tools using FastMCP decorators."""

        @self.mcp.tool()
        async def copy_user_permissions(
            source_user: str,
            target_users: List[str],
            include_groups: bool = True,
            dry_run: bool = False,
            ctx: Context = None
        ) -> str:
            """
            Copy all permissions from source user to target user(s).

            Args:
                source_user: Username to copy permissions from
                target_users: List of usernames to copy permissions to
                include_groups: Whether to copy group memberships
                dry_run: Preview changes without applying them
                ctx: FastMCP context for logging and progress reporting
            """
            try:
                # Log operation start
                if ctx:
                    await ctx.info(f"Starting permission copy from {source_user} to {len(target_users)} users")

                # Ensure SAP BO authentication
                if not await self.authenticator.ensure_authenticated():
                    raise ToolError("Failed to authenticate with SAP BusinessObjects server")

                # Report progress
                if ctx:
                    await ctx.report_progress(0, len(target_users), "Initializing permission copy")

                result = await self.permission_manager.copy_permissions(
                    source_user, target_users, include_groups, dry_run
                )

                # Log completion
                if ctx:
                    await ctx.info(f"Permission copy completed successfully")
                    await ctx.report_progress(len(target_users), len(target_users), "Complete")

                return result

            except Exception as e:
                error_msg = f"Permission copy failed: {str(e)}"
                if ctx:
                    await ctx.error(error_msg)
                raise ToolError(error_msg)

        @self.mcp.tool()
        async def manage_report_mailing_list(
            report_name: str,
            action: str,  # "add", "remove", "list"
            email_addresses: List[str] = None,
            dry_run: bool = False,
            ctx: Context = None
        ) -> str:
            """
            Add or remove email addresses from recurring report instances.

            Args:
                report_name: Name of the report to modify
                action: Action to perform ("add", "remove", "list")
                email_addresses: Email addresses to add or remove
                dry_run: Preview changes without applying them
                ctx: FastMCP context for logging and session management
            """
            try:
                # Validate inputs
                if action in ["add", "remove"] and not email_addresses:
                    raise ToolError(f"Email addresses required for '{action}' action")

                if action not in ["add", "remove", "list"]:
                    raise ToolError(f"Invalid action '{action}'. Must be 'add', 'remove', or 'list'")

                # Log operation
                if ctx:
                    await ctx.info(f"Managing mailing list for report '{report_name}' - action: {action}")

                # Ensure authentication
                if not await self.authenticator.ensure_authenticated():
                    raise ToolError("Failed to authenticate with SAP BusinessObjects server")

                result = await self.email_manager.manage_mailing_list(
                    report_name, action, email_addresses or [], dry_run
                )

                # Log success
                if ctx:
                    await ctx.info(f"Mailing list management completed for '{report_name}'")

                return result

            except Exception as e:
                error_msg = f"Mailing list management failed: {str(e)}"
                if ctx:
                    await ctx.error(error_msg)
                raise ToolError(error_msg)

        @self.mcp.tool()
        async def diagnose_crystal_reports(
            report_ids: List[str] = None,
            auto_fix: bool = False,
            generate_report: bool = True,
            ctx: Context = None
        ) -> str:
            """
            Run health checks and diagnostics on Crystal Reports.

            Args:
                report_ids: Specific report IDs to check (empty for all)
                auto_fix: Automatically fix common issues
                generate_report: Generate detailed diagnostic report
                ctx: FastMCP context for progress reporting and logging
            """
            try:
                # Log diagnostic start
                if ctx:
                    scope = f"{len(report_ids)} reports" if report_ids else "all reports"
                    await ctx.info(f"Starting Crystal Reports diagnostics for {scope}")

                # Ensure authentication
                if not await self.authenticator.ensure_authenticated():
                    raise ToolError("Failed to authenticate with SAP BusinessObjects server")

                # Report initial progress
                if ctx:
                    await ctx.report_progress(0, 100, "Initializing diagnostics")

                result = await self.diagnostics.diagnose_reports(
                    report_ids or [], auto_fix, generate_report
                )

                # Log completion
                if ctx:
                    await ctx.info("Crystal Reports diagnostics completed")
                    await ctx.report_progress(100, 100, "Diagnostics complete")

                return result

            except Exception as e:
                error_msg = f"Crystal Reports diagnostics failed: {str(e)}"
                if ctx:
                    await ctx.error(error_msg)
                raise ToolError(error_msg)

        @self.mcp.tool()
        async def list_user_permissions(
            username: str,
            include_groups: bool = True,
            ctx: Context = None
        ) -> str:
            """
            Get detailed permission information for a user.

            Args:
                username: Username to get permissions for
                include_groups: Include group membership details
                ctx: FastMCP context for logging
            """
            try:
                if ctx:
                    await ctx.info(f"Retrieving permissions for user '{username}'")

                # Ensure authentication
                if not await self.authenticator.ensure_authenticated():
                    raise ToolError("Failed to authenticate with SAP BusinessObjects server")

                result = await self.permission_manager.list_user_permissions(
                    username, include_groups
                )

                if ctx:
                    await ctx.info(f"Permission retrieval completed for '{username}'")

                return result

            except Exception as e:
                error_msg = f"Permission listing failed: {str(e)}"
                if ctx:
                    await ctx.error(error_msg)
                raise ToolError(error_msg)

        @self.mcp.tool()
        async def bulk_update_email_lists(
            updates: List[Dict[str, Any]],
            dry_run: bool = False,
            ctx: Context = None
        ) -> str:
            """
            Update multiple report mailing lists at once.

            Args:
                updates: List of email list updates to perform
                dry_run: Preview changes without applying them
                ctx: FastMCP context for progress tracking
            """
            try:
                if not updates:
                    raise ToolError("No updates provided")

                # Check security limits
                max_operations = self.config.security.max_bulk_operations
                if len(updates) > max_operations:
                    raise ToolError(f"Too many operations. Maximum allowed: {max_operations}")

                if ctx:
                    await ctx.info(f"Starting bulk update of {len(updates)} report mailing lists")
                    await ctx.report_progress(0, len(updates), "Initializing bulk updates")

                # Ensure authentication
                if not await self.authenticator.ensure_authenticated():
                    raise ToolError("Failed to authenticate with SAP BusinessObjects server")

                result = await self.email_manager.bulk_update_email_lists(updates, dry_run)

                if ctx:
                    await ctx.info("Bulk email list updates completed")
                    await ctx.report_progress(len(updates), len(updates), "All updates complete")

                return result

            except Exception as e:
                error_msg = f"Bulk email updates failed: {str(e)}"
                if ctx:
                    await ctx.error(error_msg)
                raise ToolError(error_msg)

        @self.mcp.resource("sap-bo://connection-status")
        async def connection_status(ctx: Context = None) -> Dict[str, Any]:
            """
            Get SAP BusinessObjects connection status and server information.

            Returns real-time connection status, authentication state, and server details.
            """
            try:
                if ctx:
                    await ctx.info("Checking SAP BusinessObjects connection status")

                # Test connection and authentication
                connection_result = await self.authenticator.test_connection()

                # Add additional server information
                status = {
                    "server_url": self.config.sap_bo.server_url,
                    "cms_name": self.config.sap_bo.cms_name,
                    "connection_status": connection_result,
                    "server_version": "4.3 SP02+",
                    "authentication_type": self.config.sap_bo.auth_type,
                    "readonly_mode": self.config.is_read_only(),
                    "audit_enabled": self.config.is_audit_enabled()
                }

                return status

            except Exception as e:
                if ctx:
                    await ctx.error(f"Connection status check failed: {str(e)}")
                return {"error": str(e), "connected": False}

        @self.mcp.prompt()
        async def sap_bo_admin_assistant(
            task_description: str,
            safety_level: str = "standard",
            ctx: Context = None
        ) -> str:
            """
            Strategic SAP BusinessObjects administration assistant prompt.

            Provides step-by-step guidance for complex administration tasks
            using the available MCP tools in the correct sequence.
            """
            safety_instructions = {
                "conservative": "Always use dry_run=true first, require explicit confirmation before applying changes",
                "standard": "Use dry_run for bulk operations, apply single changes directly with confirmation",
                "aggressive": "Apply changes directly but with comprehensive audit logging"
            }

            safety_mode = safety_instructions.get(safety_level, safety_instructions["standard"])

            prompt_template = f"""
You are an expert SAP BusinessObjects administrator with access to enterprise MCP tools.

**Task**: {task_description}

**Safety Mode**: {safety_mode}

**Available Tools**:
1. `copy_user_permissions` - Copy permissions between users with group support
2. `manage_report_mailing_list` - Add/remove emails from recurring reports
3. `diagnose_crystal_reports` - Health checks and auto-fix capabilities
4. `list_user_permissions` - Detailed permission analysis
5. `bulk_update_email_lists` - Batch operations for multiple reports

**Strategic Approach**:
1. **Assess**: Use `list_user_permissions` or `connection_status` to understand current state
2. **Plan**: Determine the sequence of operations needed
3. **Test**: Use dry_run mode for any bulk or destructive operations
4. **Execute**: Apply changes with progress monitoring
5. **Verify**: Confirm results and document changes

**Enterprise Considerations**:
- Always maintain audit trails
- Use session context for progress reporting
- Handle errors gracefully with fallback options
- Consider impact on customer-facing reports
- Verify permissions before making changes

Please proceed with the task using this strategic framework.
"""

            if ctx:
                await ctx.info(f"Generated administration strategy for: {task_description}")

            return prompt_template

    def run(self, host: str = "localhost", port: int = 8000):
        """Run the FastMCP server."""
        logger.info(f"Starting SAP BusinessObjects FastMCP Server on {host}:{port}")
        logger.info(f"Authentication: {'Enabled' if self.mcp.auth else 'Disabled'}")
        logger.info(f"Read-only mode: {self.config.is_read_only()}")
        logger.info(f"Audit logging: {self.config.is_audit_enabled()}")

        # Start the server
        self.mcp.run(host=host, port=port)

    async def run_stdio(self):
        """Run the server in stdio mode for Claude Desktop integration."""
        logger.info("Starting SAP BusinessObjects FastMCP Server in stdio mode")
        await self.mcp.run_stdio()


# Factory functions for different deployment scenarios
def create_development_server():
    """Create server for development (no auth, debug logging)."""
    return SAPBusinessObjectsFastMCPServer(enable_auth=False)


def create_production_server():
    """Create server for production (with auth, security hardening)."""
    return SAPBusinessObjectsFastMCPServer(enable_auth=True)


async def main():
    """Main entry point for the FastMCP server."""
    import os

    # Determine deployment mode
    deployment_mode = os.getenv("SAP_BO_DEPLOYMENT", "development")

    if deployment_mode == "production":
        server = create_production_server()
        logger.info("Starting in PRODUCTION mode with authentication")
    else:
        server = create_development_server()
        logger.info("Starting in DEVELOPMENT mode")

    # Check if running in stdio mode (for Claude Desktop)
    if os.getenv("SAP_BO_MODE") == "stdio":
        await server.run_stdio()
    else:
        # Run as HTTP server
        host = os.getenv("SAP_BO_HOST", "localhost")
        port = int(os.getenv("SAP_BO_PORT", "8000"))
        server.run(host=host, port=port)


if __name__ == "__main__":
    asyncio.run(main())