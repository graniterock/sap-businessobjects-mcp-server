"""Configuration management for SAP BusinessObjects MCP Server."""

import json
import os
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class SAPBOConfig(BaseModel):
    """SAP BusinessObjects connection configuration."""
    server_url: str = Field(..., description="SAP BO server URL")
    cms_name: str = Field(..., description="CMS name")
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")
    auth_type: str = Field(default="secEnterprise", description="Authentication type")
    timeout: int = Field(default=30, description="Request timeout in seconds")


class MCPConfig(BaseModel):
    """MCP server configuration."""
    server_name: str = Field(default="sap-businessobjects", description="Server name")
    version: str = Field(default="1.0.0", description="Server version")
    host: str = Field(default="localhost", description="Host address")
    port: int = Field(default=8080, description="Port number")


class SecurityConfig(BaseModel):
    """Security and safety configuration."""
    read_only_mode: bool = Field(default=False, description="Enable read-only mode")
    require_confirmation: bool = Field(default=True, description="Require confirmation for changes")
    audit_enabled: bool = Field(default=True, description="Enable audit logging")
    max_bulk_operations: int = Field(default=100, description="Maximum bulk operations per request")


class EmailConfig(BaseModel):
    """Email configuration for notifications."""
    smtp_server: Optional[str] = Field(default=None, description="SMTP server")
    smtp_port: int = Field(default=587, description="SMTP port")
    use_tls: bool = Field(default=True, description="Use TLS encryption")
    notification_email: Optional[str] = Field(default=None, description="Admin notification email")


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field(default="INFO", description="Logging level")
    file_path: str = Field(default="logs/sap-bo-mcp.log", description="Log file path")
    max_file_size: str = Field(default="10MB", description="Maximum log file size")
    backup_count: int = Field(default=5, description="Number of backup log files")


class Config(BaseSettings):
    """Main configuration class."""

    sap_bo: SAPBOConfig
    mcp: MCPConfig = MCPConfig()
    security: SecurityConfig = SecurityConfig()
    email: EmailConfig = EmailConfig()
    logging: LoggingConfig = LoggingConfig()

    class Config:
        env_prefix = "SAP_BO_MCP_"
        case_sensitive = False

    @classmethod
    def from_file(cls, config_path: str = "config/config.json") -> "Config":
        """Load configuration from JSON file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, 'r') as f:
            config_data = json.load(f)

        return cls(**config_data)

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls()

    def get_rest_api_base_url(self) -> str:
        """Get the base URL for SAP BO REST API."""
        base_url = self.sap_bo.server_url.rstrip('/')
        return f"{base_url}/biprws"

    def get_auth_url(self) -> str:
        """Get the authentication URL."""
        return f"{self.get_rest_api_base_url()}/logon/long"

    def get_cms_query_url(self) -> str:
        """Get the CMS query URL."""
        return f"{self.get_rest_api_base_url()}/v1/cmsquery"

    def is_read_only(self) -> bool:
        """Check if server is in read-only mode."""
        return self.security.read_only_mode

    def requires_confirmation(self) -> bool:
        """Check if operations require confirmation."""
        return self.security.require_confirmation

    def is_audit_enabled(self) -> bool:
        """Check if audit logging is enabled."""
        return self.security.audit_enabled