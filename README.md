# SAP BusinessObjects MCP Server

A Model Context Protocol (MCP) server for SAP BusinessObjects 4.3 SP02+ administration, enabling AI assistants like Claude to directly manage user permissions, email lists, and Crystal Reports diagnostics.

## Features

- **User Permission Management**: Copy permissions between users, manage group memberships
- **Email List Management**: Add/remove emails from recurring report instances
- **Crystal Reports Diagnostics**: Health checks and automated issue resolution
- **Audit Trail**: Complete logging of all administrative actions

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure SAP BO connection
cp config/config.example.json config/config.json
# Edit config.json with your SAP BO server details

# Start MCP server
python src/server.py
```

## MCP Tools

### User Management
- `copy_user_permissions` - Copy all permissions from source user to target user(s)
- `list_user_permissions` - Get detailed permission information for a user
- `audit_permission_changes` - View history of permission modifications

### Email Management
- `manage_report_mailing_list` - Add/remove emails from recurring report instances
- `list_report_recipients` - Show current mailing list for a report
- `bulk_update_email_lists` - Update multiple reports at once

### Diagnostics
- `diagnose_crystal_reports` - Run health checks on Crystal Reports
- `check_system_health` - Overall SAP BO system status
- `auto_fix_common_issues` - Automatically resolve known problems

## Configuration

See `config/config.example.json` for required connection parameters:
- SAP BO server URL
- Authentication credentials
- Default timeout settings
- Email configuration

## Security

- All credentials stored securely
- Audit trail for all operations
- Read-only mode available
- Role-based access control

## Use Cases

Perfect for organizations that need to:
- Frequently copy user permissions for new hires
- Manage mailing lists for customer-facing reports
- Automate Crystal Reports maintenance
- Provide AI-powered SAP BO administration

## License

MIT License - see LICENSE file for details