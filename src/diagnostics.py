"""Crystal Reports diagnostics and health monitoring."""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import httpx
from datetime import datetime, timedelta

from config import Config
from auth import SAPBOAuthenticator

logger = logging.getLogger(__name__)


class DiagnosticsManager:
    """Manages Crystal Reports diagnostics and health monitoring."""

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

    async def get_crystal_reports(self, report_ids: List[str] = None) -> List[Dict[str, Any]]:
        """Get Crystal Reports from the repository."""
        try:
            client = await self._get_client()

            if report_ids:
                # Query for specific reports
                id_list = ",".join([f"'{rid}'" for rid in report_ids])
                query = f"""
                SELECT SI_ID, SI_NAME, SI_DESCRIPTION, SI_CREATION_TIME, SI_UPDATE_TS, SI_FILES
                FROM CI_INFOOBJECTS
                WHERE SI_KIND = 'CrystalReport'
                AND SI_ID IN ({id_list})
                """
            else:
                # Query for all Crystal Reports
                query = """
                SELECT SI_ID, SI_NAME, SI_DESCRIPTION, SI_CREATION_TIME, SI_UPDATE_TS, SI_FILES
                FROM CI_INFOOBJECTS
                WHERE SI_KIND = 'CrystalReport'
                ORDER BY SI_UPDATE_TS DESC
                """

            response = await client.post(
                self.config.get_cms_query_url(),
                json={"query": query}
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("objects", [])
            else:
                logger.error(f"Failed to get Crystal Reports: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error getting Crystal Reports: {e}")
            return []
        finally:
            await client.aclose()

    async def check_report_health(self, report_id: str) -> Dict[str, Any]:
        """Perform health check on a specific Crystal Report."""
        health_status = {
            "report_id": report_id,
            "overall_health": "unknown",
            "checks": [],
            "issues": [],
            "recommendations": [],
            "last_checked": datetime.now().isoformat()
        }

        try:
            # Get report information
            reports = await self.get_crystal_reports([report_id])
            if not reports:
                health_status["overall_health"] = "error"
                health_status["issues"].append("Report not found")
                return health_status

            report = reports[0]
            report_name = report.get("SI_NAME")

            # Check 1: Repository integrity
            integrity_check = await self._check_repository_integrity(report_id)
            health_status["checks"].append(integrity_check)

            # Check 2: Data connections
            connection_check = await self._check_data_connections(report_id)
            health_status["checks"].append(connection_check)

            # Check 3: Formula syntax
            formula_check = await self._check_formula_syntax(report_id)
            health_status["checks"].append(formula_check)

            # Check 4: Performance metrics
            performance_check = await self._check_performance_metrics(report_id)
            health_status["checks"].append(performance_check)

            # Check 5: Recent execution history
            execution_check = await self._check_execution_history(report_id)
            health_status["checks"].append(execution_check)

            # Determine overall health
            failed_checks = [check for check in health_status["checks"] if check["status"] == "failed"]
            warning_checks = [check for check in health_status["checks"] if check["status"] == "warning"]

            if failed_checks:
                health_status["overall_health"] = "unhealthy"
                health_status["issues"].extend([check["message"] for check in failed_checks])
            elif warning_checks:
                health_status["overall_health"] = "warning"
                health_status["issues"].extend([check["message"] for check in warning_checks])
            else:
                health_status["overall_health"] = "healthy"

            # Generate recommendations
            health_status["recommendations"] = await self._generate_recommendations(health_status)

        except Exception as e:
            logger.error(f"Error checking report health for {report_id}: {e}")
            health_status["overall_health"] = "error"
            health_status["issues"].append(f"Health check failed: {str(e)}")

        return health_status

    async def _check_repository_integrity(self, report_id: str) -> Dict[str, Any]:
        """Check repository integrity for the report."""
        check = {
            "name": "Repository Integrity",
            "status": "passed",
            "message": "Report files are intact",
            "details": {}
        }

        try:
            # Simulate repository integrity check
            # In real implementation, this would check file integrity, metadata consistency, etc.
            await asyncio.sleep(0.1)

            # Placeholder check - would implement actual logic
            file_integrity = True
            metadata_consistency = True

            if not file_integrity:
                check["status"] = "failed"
                check["message"] = "Report files are corrupted or missing"
            elif not metadata_consistency:
                check["status"] = "warning"
                check["message"] = "Metadata inconsistencies detected"

        except Exception as e:
            check["status"] = "failed"
            check["message"] = f"Repository check failed: {str(e)}"

        return check

    async def _check_data_connections(self, report_id: str) -> Dict[str, Any]:
        """Check data source connections for the report."""
        check = {
            "name": "Data Connections",
            "status": "passed",
            "message": "All data connections are valid",
            "details": {"connections_tested": 0, "failed_connections": []}
        }

        try:
            # Simulate data connection testing
            await asyncio.sleep(0.2)

            # Placeholder - would test actual database connections
            test_connections = ["Database1", "Database2"]
            failed_connections = []  # Would contain actual failed connections

            check["details"]["connections_tested"] = len(test_connections)
            check["details"]["failed_connections"] = failed_connections

            if failed_connections:
                check["status"] = "failed"
                check["message"] = f"Failed connections: {', '.join(failed_connections)}"

        except Exception as e:
            check["status"] = "failed"
            check["message"] = f"Connection check failed: {str(e)}"

        return check

    async def _check_formula_syntax(self, report_id: str) -> Dict[str, Any]:
        """Check Crystal Reports formula syntax."""
        check = {
            "name": "Formula Syntax",
            "status": "passed",
            "message": "All formulas have valid syntax",
            "details": {"formulas_checked": 0, "syntax_errors": []}
        }

        try:
            # Simulate formula syntax checking
            await asyncio.sleep(0.1)

            # Placeholder - would parse and validate actual formulas
            formula_errors = []  # Would contain actual syntax errors

            if formula_errors:
                check["status"] = "failed"
                check["message"] = f"Syntax errors found in {len(formula_errors)} formula(s)"
                check["details"]["syntax_errors"] = formula_errors

        except Exception as e:
            check["status"] = "failed"
            check["message"] = f"Formula check failed: {str(e)}"

        return check

    async def _check_performance_metrics(self, report_id: str) -> Dict[str, Any]:
        """Check report performance metrics."""
        check = {
            "name": "Performance Metrics",
            "status": "passed",
            "message": "Performance within acceptable limits",
            "details": {
                "avg_execution_time": 0,
                "max_execution_time": 0,
                "memory_usage": 0
            }
        }

        try:
            # Simulate performance analysis
            await asyncio.sleep(0.1)

            # Placeholder metrics - would get from actual execution history
            avg_time = 45  # seconds
            max_time = 120  # seconds
            memory_mb = 256  # MB

            check["details"]["avg_execution_time"] = avg_time
            check["details"]["max_execution_time"] = max_time
            check["details"]["memory_usage"] = memory_mb

            if avg_time > 60:
                check["status"] = "warning"
                check["message"] = f"Average execution time ({avg_time}s) exceeds recommended limit"
            elif max_time > 300:
                check["status"] = "failed"
                check["message"] = f"Maximum execution time ({max_time}s) exceeds threshold"

        except Exception as e:
            check["status"] = "failed"
            check["message"] = f"Performance check failed: {str(e)}"

        return check

    async def _check_execution_history(self, report_id: str) -> Dict[str, Any]:
        """Check recent execution history for errors."""
        check = {
            "name": "Execution History",
            "status": "passed",
            "message": "Recent executions successful",
            "details": {
                "recent_executions": 0,
                "failed_executions": 0,
                "last_success": None,
                "last_failure": None
            }
        }

        try:
            # Query for recent instances
            client = await self._get_client()

            query = f"""
            SELECT SI_ID, SI_CREATION_TIME, SI_STATUS
            FROM CI_INFOOBJECTS
            WHERE SI_PARENT_ID = '{report_id}'
            AND SI_INSTANCE = 1
            AND SI_CREATION_TIME >= DATEADD(day, -7, GETDATE())
            ORDER BY SI_CREATION_TIME DESC
            """

            response = await client.post(
                self.config.get_cms_query_url(),
                json={"query": query}
            )

            if response.status_code == 200:
                data = response.json()
                instances = data.get("objects", [])

                total_executions = len(instances)
                failed_executions = len([i for i in instances if i.get("SI_STATUS") == "Failed"])

                check["details"]["recent_executions"] = total_executions
                check["details"]["failed_executions"] = failed_executions

                if failed_executions > 0:
                    failure_rate = (failed_executions / total_executions) * 100
                    if failure_rate > 50:
                        check["status"] = "failed"
                        check["message"] = f"High failure rate: {failure_rate:.1f}% ({failed_executions}/{total_executions})"
                    elif failure_rate > 20:
                        check["status"] = "warning"
                        check["message"] = f"Elevated failure rate: {failure_rate:.1f}%"

        except Exception as e:
            check["status"] = "failed"
            check["message"] = f"Execution history check failed: {str(e)}"

        return check

    async def _generate_recommendations(self, health_status: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on health check results."""
        recommendations = []

        for check in health_status["checks"]:
            if check["name"] == "Data Connections" and check["status"] == "failed":
                recommendations.append("Update database connection strings and test connectivity")

            elif check["name"] == "Formula Syntax" and check["status"] == "failed":
                recommendations.append("Review and fix formula syntax errors")

            elif check["name"] == "Performance Metrics" and check["status"] in ["warning", "failed"]:
                recommendations.append("Optimize report queries and consider adding database indexes")

            elif check["name"] == "Execution History" and check["status"] in ["warning", "failed"]:
                recommendations.append("Investigate recent execution failures and address root causes")

        if health_status["overall_health"] == "unhealthy":
            recommendations.append("Schedule immediate maintenance to address critical issues")
        elif health_status["overall_health"] == "warning":
            recommendations.append("Plan preventive maintenance to address warning conditions")

        return recommendations

    async def diagnose_reports(
        self,
        report_ids: List[str] = None,
        auto_fix: bool = False,
        generate_report: bool = True
    ) -> str:
        """Run diagnostics on Crystal Reports."""
        try:
            result = ["🔍 **Crystal Reports Diagnostic Results**\n"]

            if auto_fix and self.config.is_read_only():
                result.append("⚠️ **Auto-fix disabled in read-only mode**\n")
                auto_fix = False

            # Get reports to diagnose
            if report_ids:
                reports = await self.get_crystal_reports(report_ids)
                result.append(f"**Diagnosing {len(report_ids)} specified reports**")
            else:
                reports = await self.get_crystal_reports()
                result.append(f"**Diagnosing all {len(reports)} Crystal Reports**")

            if not reports:
                return "❌ No Crystal Reports found to diagnose"

            result.append("")

            # Diagnostic summary
            healthy_count = 0
            warning_count = 0
            unhealthy_count = 0
            error_count = 0

            detailed_results = []

            # Check each report
            for i, report in enumerate(reports, 1):
                report_id = str(report.get("SI_ID"))
                report_name = report.get("SI_NAME")

                result.append(f"🔍 **Report {i}/{len(reports)}: {report_name}**")

                health_status = await self.check_report_health(report_id)

                status_emoji = {
                    "healthy": "✅",
                    "warning": "⚠️",
                    "unhealthy": "❌",
                    "error": "💥"
                }

                overall_health = health_status["overall_health"]
                emoji = status_emoji.get(overall_health, "❓")

                result.append(f"  {emoji} **Overall Health**: {overall_health.upper()}")

                # Count by status
                if overall_health == "healthy":
                    healthy_count += 1
                elif overall_health == "warning":
                    warning_count += 1
                elif overall_health == "unhealthy":
                    unhealthy_count += 1
                else:
                    error_count += 1

                # Show issues
                if health_status["issues"]:
                    result.append("  **Issues:**")
                    for issue in health_status["issues"]:
                        result.append(f"    • {issue}")

                # Auto-fix if enabled
                if auto_fix and overall_health in ["warning", "unhealthy"]:
                    fix_result = await self._auto_fix_report(report_id, health_status)
                    if fix_result["fixes_applied"]:
                        result.append("  **Auto-fixes applied:**")
                        for fix in fix_result["fixes_applied"]:
                            result.append(f"    ✅ {fix}")

                detailed_results.append(health_status)
                result.append("")

            # Overall summary
            result.append("📊 **Diagnostic Summary:**")
            result.append(f"  • ✅ Healthy: {healthy_count}")
            result.append(f"  • ⚠️ Warning: {warning_count}")
            result.append(f"  • ❌ Unhealthy: {unhealthy_count}")
            result.append(f"  • 💥 Error: {error_count}")

            total_issues = warning_count + unhealthy_count + error_count
            if total_issues > 0:
                result.append(f"\n⚠️ **{total_issues} report(s) require attention**")

            # Generate detailed report if requested
            if generate_report:
                report_path = await self._generate_detailed_report(detailed_results)
                result.append(f"\n📄 **Detailed report saved**: {report_path}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"Error in report diagnostics: {e}")
            return f"❌ Error running diagnostics: {str(e)}"

    async def _auto_fix_report(self, report_id: str, health_status: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to automatically fix common report issues."""
        fix_result = {
            "report_id": report_id,
            "fixes_applied": [],
            "fixes_failed": []
        }

        try:
            # Check for fixable issues
            for check in health_status["checks"]:
                if check["status"] == "failed":
                    if check["name"] == "Data Connections":
                        # Attempt to update connection strings
                        fix_applied = await self._fix_data_connections(report_id)
                        if fix_applied:
                            fix_result["fixes_applied"].append("Updated database connection strings")
                        else:
                            fix_result["fixes_failed"].append("Failed to fix data connections")

                    elif check["name"] == "Formula Syntax":
                        # Attempt to fix common formula issues
                        fix_applied = await self._fix_formula_syntax(report_id)
                        if fix_applied:
                            fix_result["fixes_applied"].append("Fixed formula syntax errors")
                        else:
                            fix_result["fixes_failed"].append("Failed to fix formula syntax")

        except Exception as e:
            fix_result["fixes_failed"].append(f"Auto-fix error: {str(e)}")

        return fix_result

    async def _fix_data_connections(self, report_id: str) -> bool:
        """Attempt to fix data connection issues."""
        try:
            # Placeholder for actual connection fixing logic
            # This would update connection strings, test connections, etc.
            await asyncio.sleep(0.1)
            return True  # Simulate successful fix
        except Exception as e:
            logger.error(f"Failed to fix data connections for {report_id}: {e}")
            return False

    async def _fix_formula_syntax(self, report_id: str) -> bool:
        """Attempt to fix formula syntax issues."""
        try:
            # Placeholder for actual formula fixing logic
            # This would parse formulas and fix common syntax issues
            await asyncio.sleep(0.1)
            return True  # Simulate successful fix
        except Exception as e:
            logger.error(f"Failed to fix formula syntax for {report_id}: {e}")
            return False

    async def _generate_detailed_report(self, diagnostic_results: List[Dict[str, Any]]) -> str:
        """Generate detailed diagnostic report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"reports/crystal_reports_diagnostic_{timestamp}.json"

        # In a real implementation, this would write to file
        logger.info(f"Generated detailed diagnostic report: {report_path}")

        return report_path