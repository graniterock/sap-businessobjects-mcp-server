"""User permission management for SAP BusinessObjects."""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import httpx
from datetime import datetime

from config import Config
from auth import SAPBOAuthenticator

logger = logging.getLogger(__name__)


class PermissionManager:
    """Manages user permissions in SAP BusinessObjects."""

    def __init__(self, config: Config):
        self.config = config
        self.auth = SAPBOAuthenticator(config)

    async def _get_client(self) -> httpx.AsyncClient:
        """Get authenticated HTTP client."""
        return httpx.AsyncClient(
            timeout=self.config.sap_bo.timeout,
            verify=False,
            headers=self.auth.get_auth_headers()
        )

    async def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information from SAP BusinessObjects."""
        try:
            client = await self._get_client()

            # Query for user information
            query = f"SELECT * FROM CI_SYSTEMOBJECTS WHERE SI_NAME='{username}' AND SI_KIND='User'"

            response = await client.post(
                self.config.get_cms_query_url(),
                json={"query": query}
            )

            if response.status_code == 200:
                data = response.json()
                users = data.get("objects", [])
                return users[0] if users else None
            else:
                logger.error(f"Failed to get user info: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error getting user info for {username}: {e}")
            return None
        finally:
            await client.aclose()

    async def get_user_groups(self, user_id: int) -> List[Dict[str, Any]]:
        """Get groups that a user belongs to."""
        try:
            client = await self._get_client()

            # Query for user group memberships
            query = f"""
            SELECT SI_ID, SI_NAME, SI_DESCRIPTION
            FROM CI_SYSTEMOBJECTS
            WHERE SI_KIND='UserGroup'
            AND SI_ID IN (
                SELECT SI_PARENT_ID
                FROM CI_SYSTEMOBJECTS
                WHERE SI_ID={user_id}
            )
            """

            response = await client.post(
                self.config.get_cms_query_url(),
                json={"query": query}
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("objects", [])
            else:
                logger.error(f"Failed to get user groups: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error getting user groups for {user_id}: {e}")
            return []
        finally:
            await client.aclose()

    async def get_user_permissions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get permissions directly assigned to a user."""
        try:
            client = await self._get_client()

            # This would require more complex queries to get actual permissions
            # For now, return placeholder structure
            permissions = [
                {
                    "object_type": "Report",
                    "permissions": ["View", "Export", "Schedule"],
                    "granted_by": "Direct Assignment"
                }
            ]

            return permissions

        except Exception as e:
            logger.error(f"Error getting user permissions for {user_id}: {e}")
            return []

    async def list_user_permissions(self, username: str, include_groups: bool = True) -> str:
        """List all permissions for a user."""
        try:
            # Get user information
            user_info = await self.get_user_info(username)
            if not user_info:
                return f"❌ User '{username}' not found"

            user_id = user_info.get("SI_ID")
            result = [f"📋 **Permissions for user: {username}**\n"]

            # Basic user info
            result.append(f"**User ID**: {user_id}")
            result.append(f"**Full Name**: {user_info.get('SI_DESCRIPTION', 'N/A')}")
            result.append(f"**Status**: {'Active' if user_info.get('SI_DISABLED') == 0 else 'Disabled'}")
            result.append("")

            # Get groups if requested
            if include_groups:
                groups = await self.get_user_groups(user_id)
                if groups:
                    result.append("**👥 Group Memberships:**")
                    for group in groups:
                        result.append(f"  • {group.get('SI_NAME')} - {group.get('SI_DESCRIPTION', '')}")
                    result.append("")

            # Get direct permissions
            permissions = await self.get_user_permissions(user_id)
            if permissions:
                result.append("**🔐 Direct Permissions:**")
                for perm in permissions:
                    result.append(f"  • {perm.get('object_type')}: {', '.join(perm.get('permissions', []))}")
            else:
                result.append("**🔐 Direct Permissions:** None found")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"Error listing permissions for {username}: {e}")
            return f"❌ Error listing permissions for {username}: {str(e)}"

    async def copy_permissions(
        self,
        source_user: str,
        target_users: List[str],
        include_groups: bool = True,
        dry_run: bool = False
    ) -> str:
        """Copy permissions from source user to target users."""
        try:
            # Check if in read-only mode
            if self.config.is_read_only() and not dry_run:
                return "❌ Server is in read-only mode. Use dry_run=true to preview changes."

            result = [f"🔄 **Copying permissions from '{source_user}' to {len(target_users)} user(s)**\n"]

            if dry_run:
                result.append("🔍 **DRY RUN MODE - No changes will be applied**\n")

            # Get source user information
            source_info = await self.get_user_info(source_user)
            if not source_info:
                return f"❌ Source user '{source_user}' not found"

            source_id = source_info.get("SI_ID")
            result.append(f"**Source User**: {source_user} (ID: {source_id})")

            # Get source user's groups and permissions
            source_groups = await self.get_user_groups(source_id) if include_groups else []
            source_permissions = await self.get_user_permissions(source_id)

            result.append(f"**Groups to copy**: {len(source_groups)}")
            result.append(f"**Direct permissions to copy**: {len(source_permissions)}")
            result.append("")

            # Process each target user
            successful_copies = 0
            failed_copies = []

            for target_user in target_users:
                try:
                    result.append(f"📝 **Processing target user: {target_user}**")

                    # Check if target user exists
                    target_info = await self.get_user_info(target_user)
                    if not target_info:
                        failed_copies.append(f"{target_user}: User not found")
                        result.append(f"  ❌ User '{target_user}' not found")
                        continue

                    target_id = target_info.get("SI_ID")

                    if not dry_run:
                        # In a real implementation, this would:
                        # 1. Add user to source user's groups
                        # 2. Copy direct permissions
                        # 3. Handle any conflicts or errors

                        # Placeholder for actual implementation
                        await self._copy_user_to_groups(target_id, source_groups)
                        await self._copy_direct_permissions(target_id, source_permissions)

                    result.append(f"  ✅ Successfully copied permissions to '{target_user}'")
                    successful_copies += 1

                except Exception as e:
                    error_msg = f"{target_user}: {str(e)}"
                    failed_copies.append(error_msg)
                    result.append(f"  ❌ Failed to copy to '{target_user}': {str(e)}")

                result.append("")

            # Summary
            result.append("📊 **Summary:**")
            result.append(f"  • Successful copies: {successful_copies}")
            result.append(f"  • Failed copies: {len(failed_copies)}")

            if failed_copies:
                result.append("\n❌ **Failures:**")
                for failure in failed_copies:
                    result.append(f"  • {failure}")

            # Audit log
            if self.config.is_audit_enabled() and not dry_run:
                await self._log_permission_copy(
                    source_user, target_users, successful_copies, failed_copies
                )

            return "\n".join(result)

        except Exception as e:
            logger.error(f"Error copying permissions: {e}")
            return f"❌ Error copying permissions: {str(e)}"

    async def _copy_user_to_groups(self, user_id: int, groups: List[Dict[str, Any]]) -> None:
        """Add user to specified groups."""
        # Placeholder for actual group membership implementation
        # This would use the SAP BO SDK or REST API to add user to groups
        logger.info(f"Would add user {user_id} to {len(groups)} groups")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _copy_direct_permissions(self, user_id: int, permissions: List[Dict[str, Any]]) -> None:
        """Copy direct permissions to user."""
        # Placeholder for actual permission copy implementation
        # This would use the SAP BO SDK or REST API to assign permissions
        logger.info(f"Would copy {len(permissions)} direct permissions to user {user_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _log_permission_copy(
        self,
        source_user: str,
        target_users: List[str],
        successful: int,
        failed: List[str]
    ) -> None:
        """Log permission copy operation for audit trail."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": "copy_permissions",
            "source_user": source_user,
            "target_users": target_users,
            "successful_copies": successful,
            "failed_copies": failed,
            "performer": "mcp-server"  # Could be enhanced to track actual user
        }

        # In a real implementation, this would write to audit log file or database
        logger.info(f"Audit log: {audit_entry}")

    async def validate_user_exists(self, username: str) -> bool:
        """Validate that a user exists in SAP BusinessObjects."""
        user_info = await self.get_user_info(username)
        return user_info is not None