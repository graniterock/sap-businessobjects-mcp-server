# SAP BusinessObjects MCP Server

A Model Context Protocol (MCP) server for SAP BusinessObjects 4.3 SP02+ administration, enabling AI assistants like Claude to directly manage user permissions, email lists, and Crystal Reports diagnostics.

## 🚀 **NEW: FastMCP Enterprise Edition**

We now include a **FastMCP-powered server** (`src/fastmcp_server.py`) with enterprise features:
- **🔐 Enterprise Authentication**: Google OAuth, GitHub, Auth0, Azure AD
- **📊 Session Management**: Progress reporting, context-aware operations
- **🛡️ Production Security**: Error masking, rate limiting, audit logging
- **⚡ Developer Experience**: Decorator-based tools, automatic validation
- **📈 Real-time Monitoring**: Health checks, performance metrics, status resources

## Features

- **User Permission Management**: Copy permissions between users, manage group memberships
- **Email List Management**: Add/remove emails from recurring report instances
- **Crystal Reports Diagnostics**: Health checks and automated issue resolution
- **Audit Trail**: Complete logging of all administrative actions

## Quick Start

### Standard MCP Server (Basic)
```bash
# Install dependencies
pip install -r requirements.txt

# Configure SAP BO connection
cp config/config.example.json config/config.json
# Edit config.json with your SAP BO server details

# Start standard MCP server
python src/server.py
```

### FastMCP Server (Enterprise) ⭐ **Recommended**
```bash
# Install FastMCP
pip install fastmcp>=2.0.0

# Development mode (no auth)
export SAP_BO_DEPLOYMENT=development
python src/fastmcp_server.py

# Production mode (with OAuth)
export SAP_BO_DEPLOYMENT=production
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
python src/fastmcp_server.py
```

See [FastMCP Deployment Guide](docs/FASTMCP_DEPLOYMENT.md) for complete setup instructions.

## 📊 Standard vs FastMCP Comparison

| Feature | Standard MCP | FastMCP Enterprise |
|---------|-------------|-------------------|
| **Development** | Manual tool registration | `@mcp.tool()` decorators |
| **Authentication** | None | Google, GitHub, Auth0, Azure |
| **Session Management** | Basic | Rich context with progress tracking |
| **Error Handling** | Basic exceptions | Security-hardened error masking |
| **Monitoring** | None | Real-time health checks & metrics |
| **Production Ready** | Development/Testing | Enterprise deployment |
| **Progress Reporting** | None | Built-in progress tracking |
| **Security** | Basic | Rate limiting, audit logging, CORS |
| **Deployment** | Single mode | Development/Production modes |
| **AI Integration** | Basic tools | Strategic prompts & LLM sampling |

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
