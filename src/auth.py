"""Authentication module for SAP BusinessObjects REST API."""

import asyncio
import logging
from typing import Optional, Dict, Any
import httpx
from datetime import datetime, timedelta

from config import Config

logger = logging.getLogger(__name__)


class SAPBOAuthenticator:
    """Handles authentication with SAP BusinessObjects REST API."""

    def __init__(self, config: Config):
        self.config = config
        self.session_token: Optional[str] = None
        self.session_expires: Optional[datetime] = None
        self.client: Optional[httpx.AsyncClient] = None

    async def _create_client(self) -> httpx.AsyncClient:
        """Create HTTP client with proper configuration."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=self.config.sap_bo.timeout,
                verify=False,  # May need to be True in production
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            )
        return self.client

    async def authenticate(self) -> bool:
        """Authenticate with SAP BusinessObjects server."""
        try:
            client = await self._create_client()

            auth_payload = {
                "userName": self.config.sap_bo.username,
                "password": self.config.sap_bo.password,
                "auth": self.config.sap_bo.auth_type
            }

            logger.info(f"Authenticating with SAP BO server: {self.config.sap_bo.server_url}")

            response = await client.post(
                self.config.get_auth_url(),
                json=auth_payload
            )

            if response.status_code == 200:
                # Extract session token from response headers
                self.session_token = response.headers.get('X-SAP-LogonToken')

                if self.session_token:
                    # Set session expiration (typically 30 minutes)
                    self.session_expires = datetime.now() + timedelta(minutes=30)
                    logger.info("Successfully authenticated with SAP BusinessObjects")
                    return True
                else:
                    logger.error("Authentication successful but no session token received")
                    return False
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False

    async def ensure_authenticated(self) -> bool:
        """Ensure we have a valid authentication token."""
        # Check if we need to authenticate or re-authenticate
        if (self.session_token is None or
            self.session_expires is None or
            datetime.now() >= self.session_expires):

            logger.info("Session expired or missing, re-authenticating...")
            return await self.authenticate()

        return True

    async def logout(self) -> bool:
        """Logout from SAP BusinessObjects server."""
        if self.session_token is None:
            return True

        try:
            client = await self._create_client()

            response = await client.post(
                f"{self.config.get_rest_api_base_url()}/logoff",
                headers={'X-SAP-LogonToken': self.session_token}
            )

            if response.status_code == 200:
                logger.info("Successfully logged out from SAP BusinessObjects")
                self.session_token = None
                self.session_expires = None
                return True
            else:
                logger.warning(f"Logout warning: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False
        finally:
            if self.client:
                await self.client.aclose()
                self.client = None

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests."""
        if self.session_token:
            return {
                'X-SAP-LogonToken': self.session_token,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        else:
            raise RuntimeError("Not authenticated - no session token available")

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to SAP BusinessObjects server."""
        result = {
            "connected": False,
            "authenticated": False,
            "server_info": {},
            "error": None
        }

        try:
            client = await self._create_client()

            # Test basic connectivity
            response = await client.get(f"{self.config.sap_bo.server_url}/biprws")
            if response.status_code == 200:
                result["connected"] = True
                logger.info("Successfully connected to SAP BO server")
            else:
                result["error"] = f"Connection failed: {response.status_code}"
                return result

            # Test authentication
            if await self.authenticate():
                result["authenticated"] = True

                # Get server information
                info_response = await client.get(
                    f"{self.config.get_rest_api_base_url()}/v1/application",
                    headers=self.get_auth_headers()
                )

                if info_response.status_code == 200:
                    result["server_info"] = info_response.json()

            else:
                result["error"] = "Authentication failed"

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Connection test error: {e}")

        return result

    async def __aenter__(self):
        """Async context manager entry."""
        await self.ensure_authenticated()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.logout()