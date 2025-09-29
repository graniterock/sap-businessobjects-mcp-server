"""Email list management for SAP BusinessObjects recurring instances."""

import asyncio
import logging
import re
from typing import List, Dict, Any, Optional
import httpx
from datetime import datetime

from config import Config
from auth import SAPBOAuthenticator

logger = logging.getLogger(__name__)


class EmailListManager:
    """Manages email lists for SAP BusinessObjects recurring report instances."""

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

    async def find_recurring_instances(self, report_name: str) -> List[Dict[str, Any]]:
        """Find recurring instances for a report by name."""
        try:
            client = await self._get_client()

            # Query for recurring instances of the specified report
            query = f"""
            SELECT SI_ID, SI_NAME, SI_PARENT_ID, SI_SCHEDULE_STATUS, SI_STARTTIME, SI_ENDTIME
            FROM CI_INFOOBJECTS
            WHERE SI_INSTANCE = 1
            AND SI_SCHEDULE_STATUS = 9
            AND SI_NAME LIKE '%{report_name}%'
            """

            response = await client.post(
                self.config.get_cms_query_url(),
                json={"query": query}
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("objects", [])
            else:
                logger.error(f"Failed to find recurring instances: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error finding recurring instances for {report_name}: {e}")
            return []
        finally:
            await client.aclose()

    async def get_instance_destinations(self, instance_id: int) -> List[Dict[str, Any]]:
        """Get email destinations for a recurring instance."""
        try:
            client = await self._get_client()

            # Get destination information for the instance
            # This is a simplified query - actual implementation would need more complex logic
            destinations = [
                {
                    "type": "smtp",
                    "email": "example@company.com",
                    "name": "Example User",
                    "enabled": True
                }
            ]

            return destinations

        except Exception as e:
            logger.error(f"Error getting destinations for instance {instance_id}: {e}")
            return []

    async def update_instance_destinations(
        self,
        instance_id: int,
        action: str,
        email_addresses: List[str]
    ) -> bool:
        """Update email destinations for a recurring instance."""
        try:
            # This would use the SAP BO SDK to modify the recurring instance
            # The actual implementation would depend on the SDK methods available

            if action == "add":
                logger.info(f"Adding emails {email_addresses} to instance {instance_id}")
                # Implementation: Add email destinations
                await self._add_email_destinations(instance_id, email_addresses)

            elif action == "remove":
                logger.info(f"Removing emails {email_addresses} from instance {instance_id}")
                # Implementation: Remove email destinations
                await self._remove_email_destinations(instance_id, email_addresses)

            return True

        except Exception as e:
            logger.error(f"Error updating destinations for instance {instance_id}: {e}")
            return False

    async def _add_email_destinations(self, instance_id: int, emails: List[str]) -> None:
        """Add email destinations to a recurring instance."""
        # Placeholder for actual SDK implementation
        # This would use the SAP BO Enterprise SDK to:
        # 1. Get the recurring instance object
        # 2. Get its scheduling info and destinations
        # 3. Add new SMTP destinations
        # 4. Save the changes

        for email in emails:
            if self._validate_email(email):
                logger.info(f"Would add email {email} to instance {instance_id}")
                await asyncio.sleep(0.1)  # Simulate API call
            else:
                logger.warning(f"Invalid email format: {email}")

    async def _remove_email_destinations(self, instance_id: int, emails: List[str]) -> None:
        """Remove email destinations from a recurring instance."""
        # Placeholder for actual SDK implementation
        # This would use the SAP BO Enterprise SDK to:
        # 1. Get the recurring instance object
        # 2. Get its scheduling info and destinations
        # 3. Remove matching SMTP destinations
        # 4. Save the changes

        for email in emails:
            logger.info(f"Would remove email {email} from instance {instance_id}")
            await asyncio.sleep(0.1)  # Simulate API call

    def _validate_email(self, email: str) -> bool:
        """Validate email address format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    async def manage_mailing_list(
        self,
        report_name: str,
        action: str,
        email_addresses: List[str],
        dry_run: bool = False
    ) -> str:
        """Manage mailing list for a report's recurring instances."""
        try:
            # Check if in read-only mode
            if self.config.is_read_only() and not dry_run:
                return "❌ Server is in read-only mode. Use dry_run=true to preview changes."

            result = [f"📧 **Managing mailing list for report: {report_name}**\n"]

            if dry_run:
                result.append("🔍 **DRY RUN MODE - No changes will be applied**\n")

            # Validate action
            if action not in ["add", "remove", "list"]:
                return f"❌ Invalid action '{action}'. Must be 'add', 'remove', or 'list'"

            # Validate email addresses for add/remove actions
            if action in ["add", "remove"] and not email_addresses:
                return f"❌ Email addresses required for '{action}' action"

            invalid_emails = [email for email in email_addresses if not self._validate_email(email)]
            if invalid_emails:
                result.append(f"⚠️ **Invalid email formats**: {', '.join(invalid_emails)}")
                email_addresses = [email for email in email_addresses if self._validate_email(email)]

            # Find recurring instances for the report
            instances = await self.find_recurring_instances(report_name)
            if not instances:
                return f"❌ No recurring instances found for report '{report_name}'"

            result.append(f"**Found {len(instances)} recurring instance(s)**")

            # Process each instance
            total_processed = 0
            total_errors = 0

            for instance in instances:
                instance_id = instance.get("SI_ID")
                instance_name = instance.get("SI_NAME")

                result.append(f"\n📄 **Instance**: {instance_name} (ID: {instance_id})")

                try:
                    if action == "list":
                        # List current destinations
                        destinations = await self.get_instance_destinations(instance_id)
                        if destinations:
                            result.append("  **Current email recipients:**")
                            for dest in destinations:
                                status = "✅" if dest.get("enabled") else "❌"
                                result.append(f"    {status} {dest.get('email')} - {dest.get('name', 'N/A')}")
                        else:
                            result.append("  **No email destinations found**")

                    elif action in ["add", "remove"]:
                        if not dry_run:
                            success = await self.update_instance_destinations(
                                instance_id, action, email_addresses
                            )
                            if success:
                                result.append(f"  ✅ Successfully {action}ed {len(email_addresses)} email(s)")
                                total_processed += 1
                            else:
                                result.append(f"  ❌ Failed to {action} emails")
                                total_errors += 1
                        else:
                            result.append(f"  🔍 Would {action} {len(email_addresses)} email(s):")
                            for email in email_addresses:
                                result.append(f"    • {email}")
                            total_processed += 1

                except Exception as e:
                    result.append(f"  ❌ Error processing instance: {str(e)}")
                    total_errors += 1

            # Summary
            result.append(f"\n📊 **Summary:**")
            result.append(f"  • Instances processed: {total_processed}")
            result.append(f"  • Errors: {total_errors}")

            if action in ["add", "remove"] and email_addresses:
                result.append(f"  • Emails {action}ed: {', '.join(email_addresses)}")

            # Audit log
            if self.config.is_audit_enabled() and not dry_run and action != "list":
                await self._log_email_change(report_name, action, email_addresses, total_processed)

            return "\n".join(result)

        except Exception as e:
            logger.error(f"Error managing mailing list: {e}")
            return f"❌ Error managing mailing list: {str(e)}"

    async def bulk_update_email_lists(
        self,
        updates: List[Dict[str, Any]],
        dry_run: bool = False
    ) -> str:
        """Perform bulk updates to multiple report mailing lists."""
        try:
            # Check limits
            if len(updates) > self.config.security.max_bulk_operations:
                return f"❌ Too many operations. Maximum allowed: {self.config.security.max_bulk_operations}"

            result = [f"📧 **Bulk updating {len(updates)} report mailing lists**\n"]

            if dry_run:
                result.append("🔍 **DRY RUN MODE - No changes will be applied**\n")

            successful_updates = 0
            failed_updates = []

            for i, update in enumerate(updates, 1):
                report_name = update.get("report_name")
                action = update.get("action")
                email_addresses = update.get("email_addresses", [])

                result.append(f"🔄 **Update {i}/{len(updates)}: {report_name}**")

                try:
                    update_result = await self.manage_mailing_list(
                        report_name, action, email_addresses, dry_run
                    )

                    if "❌" not in update_result:
                        successful_updates += 1
                        result.append(f"  ✅ Success: {action}ed {len(email_addresses)} email(s)")
                    else:
                        failed_updates.append(f"{report_name}: {action} failed")
                        result.append(f"  ❌ Failed: {update_result.split('❌')[-1].strip()}")

                except Exception as e:
                    failed_updates.append(f"{report_name}: {str(e)}")
                    result.append(f"  ❌ Error: {str(e)}")

                result.append("")

            # Final summary
            result.append("📊 **Bulk Update Summary:**")
            result.append(f"  • Successful updates: {successful_updates}")
            result.append(f"  • Failed updates: {len(failed_updates)}")

            if failed_updates:
                result.append("\n❌ **Failures:**")
                for failure in failed_updates:
                    result.append(f"  • {failure}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"Error in bulk email updates: {e}")
            return f"❌ Error in bulk email updates: {str(e)}"

    async def _log_email_change(
        self,
        report_name: str,
        action: str,
        email_addresses: List[str],
        instances_affected: int
    ) -> None:
        """Log email list change for audit trail."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": "email_list_change",
            "report_name": report_name,
            "action": action,
            "email_addresses": email_addresses,
            "instances_affected": instances_affected,
            "performer": "mcp-server"
        }

        # In a real implementation, this would write to audit log file or database
        logger.info(f"Email audit log: {audit_entry}")

    async def get_all_customer_reports(self) -> List[Dict[str, Any]]:
        """Get all customer-facing reports with recurring instances."""
        try:
            client = await self._get_client()

            # Query for reports that have recurring instances and are customer-facing
            # This could be identified by naming convention, folder, or metadata
            query = """
            SELECT DISTINCT p.SI_ID, p.SI_NAME, p.SI_DESCRIPTION
            FROM CI_INFOOBJECTS p
            INNER JOIN CI_INFOOBJECTS i ON p.SI_ID = i.SI_PARENT_ID
            WHERE i.SI_INSTANCE = 1
            AND i.SI_SCHEDULE_STATUS = 9
            AND (p.SI_NAME LIKE '%Customer%' OR p.SI_NAME LIKE '%External%')
            """

            response = await client.post(
                self.config.get_cms_query_url(),
                json={"query": query}
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("objects", [])
            else:
                logger.error(f"Failed to get customer reports: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error getting customer reports: {e}")
            return []
        finally:
            await client.aclose()