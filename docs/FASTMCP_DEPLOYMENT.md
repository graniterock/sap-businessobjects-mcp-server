# SAP BusinessObjects FastMCP Server Deployment Guide

## Overview

This guide covers deploying the FastMCP-powered SAP BusinessObjects administration server with enterprise authentication, session management, and production-ready features.

## FastMCP vs Standard MCP

### Standard MCP Server (`src/server.py`)
- Basic MCP protocol implementation
- Manual tool registration
- Limited error handling
- No built-in authentication
- Suitable for development and testing

### FastMCP Server (`src/fastmcp_server.py`)
- **Decorator-based tools**: Simple `@mcp.tool()` decorators
- **Enterprise authentication**: Google, GitHub, Auth0, Azure integration
- **Session management**: Context objects with progress reporting
- **Error masking**: Security-hardened error responses
- **Resource endpoints**: Real-time server status monitoring
- **Strategic prompts**: AI-guided administration workflows
- **Production-ready**: Rate limiting, audit logging, CORS support

## Quick Start

### Development Mode (No Authentication)
```bash
# Install FastMCP
pip install fastmcp>=2.0.0

# Set environment
export SAP_BO_DEPLOYMENT=development
export SAP_BO_MODE=stdio  # For Claude Desktop integration

# Run development server
python src/fastmcp_server.py
```

### Production Mode (With Authentication)
```bash
# Set production environment
export SAP_BO_DEPLOYMENT=production
export SAP_BO_MODE=http
export SAP_BO_HOST=0.0.0.0
export SAP_BO_PORT=8000

# Configure authentication (see Authentication section)
# Run production server
python src/fastmcp_server.py
```

## Authentication Setup

### Google OAuth Setup
1. **Create Google OAuth App**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create new project or select existing
   - Enable Google+ API
   - Create OAuth 2.0 credentials

2. **Configure FastMCP**:
   ```python
   from fastmcp.server.auth import GoogleProvider

   auth = GoogleProvider(
       client_id="your-google-client-id.googleusercontent.com",
       client_secret="your-google-client-secret",
       base_url="https://your-server.com",
       allowed_domains=["graniterock.com"]  # Restrict to company domain
   )
   ```

3. **Environment Variables**:
   ```bash
   export GOOGLE_CLIENT_ID="your-client-id"
   export GOOGLE_CLIENT_SECRET="your-client-secret"
   export SERVER_BASE_URL="https://your-server.com"
   ```

### Auth0 Setup
```python
from fastmcp.server.auth import Auth0Provider

auth = Auth0Provider(
    domain="your-domain.auth0.com",
    client_id="your-auth0-client-id",
    client_secret="your-auth0-client-secret",
    base_url="https://your-server.com"
)
```

### GitHub Enterprise
```python
from fastmcp.server.auth import GitHubProvider

auth = GitHubProvider(
    client_id="your-github-client-id",
    client_secret="your-github-client-secret",
    base_url="https://your-server.com",
    allowed_organizations=["graniterock"]
)
```

## Enterprise Features

### Session Management with Context
FastMCP provides rich context objects for each client session:

```python
@mcp.tool()
async def advanced_operation(data: str, ctx: Context):
    # Log to client
    await ctx.info("Starting advanced operation...")

    # Report progress
    await ctx.report_progress(0, 100, "Initializing")

    # Make authenticated HTTP requests
    response = await ctx.http_request("GET", "https://api.example.com/data")

    # Access other server resources
    config_data = await ctx.read_resource("sap-bo://connection-status")

    # Sample from client's LLM
    llm_response = await ctx.sample("Analyze this data: " + data)

    return "Operation completed"
```

### Error Handling and Security
```python
# Secure error handling with masking
mcp = FastMCP(
    "sap-businessobjects-enterprise",
    mask_error_details=True  # Hide internal errors from clients
)

@mcp.tool()
async def secure_operation(ctx: Context):
    try:
        # Business logic here
        pass
    except InternalError as e:
        # This gets masked from client
        await ctx.error("Internal operation failed")
        raise ToolError("Operation failed due to system error")
    except ValidationError as e:
        # This can be shown to client
        raise ToolError(f"Invalid input: {str(e)}")
```

### Real-time Monitoring
```python
@mcp.resource("sap-bo://health")
async def health_check():
    return {
        "status": "healthy",
        "connections": await check_sap_bo_connections(),
        "performance": await get_performance_metrics(),
        "timestamp": datetime.now().isoformat()
    }
```

## Deployment Architectures

### 1. Claude Desktop Integration
```bash
# ~/.claude/claude_desktop_config.json
{
  "mcpServers": {
    "sap-businessobjects": {
      "command": "python",
      "args": ["/path/to/sap-businessobjects-mcp-server/src/fastmcp_server.py"],
      "env": {
        "SAP_BO_MODE": "stdio",
        "SAP_BO_DEPLOYMENT": "development"
      }
    }
  }
}
```

### 2. Standalone HTTP Server
```bash
# Production deployment with Docker
FROM python:3.11-slim

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

EXPOSE 8000

ENV SAP_BO_DEPLOYMENT=production
ENV SAP_BO_MODE=http
ENV SAP_BO_HOST=0.0.0.0
ENV SAP_BO_PORT=8000

CMD ["python", "src/fastmcp_server.py"]
```

### 3. Enterprise SSO Integration
```python
# Custom authentication provider
class SSOProvider(AuthProvider):
    async def authenticate(self, request):
        # Custom SAML/OIDC integration
        token = extract_sso_token(request)
        user = await validate_enterprise_token(token)
        return user

mcp = FastMCP("sap-bo-enterprise", auth=SSOProvider())
```

## Performance and Scaling

### Connection Pooling
```python
# Configure SAP BO connection pooling
config = Config()
config.sap_bo.connection_pool_size = 10
config.sap_bo.connection_timeout = 30
config.sap_bo.retry_attempts = 3
```

### Rate Limiting
```python
from fastmcp.middleware import RateLimitMiddleware

mcp = FastMCP(
    "sap-businessobjects",
    middleware=[
        RateLimitMiddleware(
            requests_per_minute=60,
            burst_allowance=10
        )
    ]
)
```

### Horizontal Scaling
- **Load Balancer**: Use nginx or HAProxy
- **Session Storage**: Redis for shared session state
- **Database**: PostgreSQL for audit logs and configuration
- **Monitoring**: Prometheus + Grafana for metrics

## Security Checklist

### Authentication
- [ ] OAuth providers configured with company domains
- [ ] Client secrets stored in environment variables
- [ ] HTTPS enforced in production
- [ ] Session timeouts configured appropriately

### Network Security
- [ ] CORS configured for allowed origins
- [ ] Rate limiting enabled
- [ ] Input validation on all endpoints
- [ ] Network isolation where possible

### Audit and Compliance
- [ ] All operations logged with user attribution
- [ ] Audit logs retained per company policy
- [ ] Error logs sanitized of sensitive information
- [ ] Regular security updates applied

### SAP BO Integration
- [ ] SAP BO credentials encrypted at rest
- [ ] Connection timeouts configured
- [ ] Read-only mode available for safety
- [ ] Dry-run capability for all destructive operations

## Monitoring and Observability

### Health Checks
```python
@mcp.resource("sap-bo://metrics")
async def metrics():
    return {
        "requests_per_minute": get_request_rate(),
        "sap_bo_response_time": await measure_sap_bo_latency(),
        "active_sessions": get_active_session_count(),
        "error_rate": get_error_rate()
    }
```

### Logging Configuration
```python
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   ```bash
   # Check OAuth configuration
   curl -X GET "https://your-server.com/.well-known/oauth-authorization-server"

   # Verify client credentials
   echo $GOOGLE_CLIENT_ID
   ```

2. **SAP BO Connection Issues**
   ```python
   # Test connection independently
   async def test_sap_bo():
       auth = SAPBOAuthenticator(config)
       result = await auth.test_connection()
       print(result)
   ```

3. **Session Management**
   ```python
   # Check session storage
   @mcp.tool()
   async def debug_session(ctx: Context):
       return {
           "session_id": ctx.session.id,
           "authenticated": ctx.session.authenticated,
           "user": ctx.session.user
       }
   ```

### Performance Optimization

1. **Connection Caching**
   - Reuse SAP BO authentication tokens
   - Pool database connections
   - Cache frequently accessed data

2. **Async Operations**
   - Use asyncio for concurrent SAP BO requests
   - Implement request batching where possible
   - Stream large result sets

3. **Memory Management**
   - Limit result set sizes
   - Implement pagination for large queries
   - Clean up resources after operations

## Migration from Standard MCP

To migrate from the standard MCP server to FastMCP:

1. **Install FastMCP**: `pip install fastmcp>=2.0.0`
2. **Update imports**: Replace MCP SDK imports with FastMCP
3. **Convert tools**: Use decorators instead of manual registration
4. **Add authentication**: Configure enterprise auth providers
5. **Update deployment**: Use new environment variables and configuration

The FastMCP server maintains backward compatibility with all existing SAP BO operations while adding enterprise features and improved developer experience.