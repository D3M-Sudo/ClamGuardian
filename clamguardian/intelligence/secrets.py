"""Secure secret storage for Threat Intelligence API keys.

Adheres strictly to the security requirement:
- Credentials managed via the operating system's Secret Service (libsecret).
- Absolutely NO plaintext fallback on disk.
- Fail closed if Secret Service is unavailable and explain the limitation.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

SECRET_SCHEMA_NAME = "io.github.clamguardian.ThreatIntelligence"
SECRET_ATTRIBUTES = {"service": "virustotal-api-key"}
SECRET_LABEL = "ClamGuardian VirusTotal API Key"


class SecretStorageError(RuntimeError):
    """Raised when Secret Service is unavailable or fails."""


class IntelligenceSecretStore:
    """Manage VirusTotal API key in OS Secret Service with fail-closed policy."""

    @staticmethod
    def is_available() -> bool:
        """Check if libsecret / Secret Service is functional in this environment."""
        try:
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret  # noqa: F401

            return True
        except Exception:
            return False

    def get_api_key(self) -> str | None:
        """Retrieve the API key from Secret Service.

        Raises SecretStorageError if Secret Service is unavailable.
        """
        try:
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            schema = Secret.Schema.new(
                SECRET_SCHEMA_NAME,
                Secret.SchemaFlags.NONE,
                {"service": Secret.SchemaAttributeType.STRING},
            )
            val = Secret.password_lookup_sync(schema, dict(SECRET_ATTRIBUTES), None)
            return val if val else None
        except Exception as exc:
            raise SecretStorageError(
                "Secure credential storage (Secret Service / libsecret) is unavailable. "
                "Plaintext credential storage is prohibited by security policy."
            ) from exc

    def set_api_key(self, api_key: str) -> None:
        """Store the API key in Secret Service.

        Raises SecretStorageError if Secret Service is unavailable or fails.
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")
        try:
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            schema = Secret.Schema.new(
                SECRET_SCHEMA_NAME,
                Secret.SchemaFlags.NONE,
                {"service": Secret.SchemaAttributeType.STRING},
            )
            success = Secret.password_store_sync(
                schema,
                dict(SECRET_ATTRIBUTES),
                Secret.COLLECTION_DEFAULT,
                SECRET_LABEL,
                api_key.strip(),
                None,
            )
            if not success:
                raise SecretStorageError("Failed to store API key in Secret Service")
        except Exception as exc:
            raise SecretStorageError(
                "Secure credential storage (Secret Service / libsecret) is unavailable. "
                "Plaintext credential storage is prohibited by security policy."
            ) from exc

    def clear_api_key(self) -> None:
        """Clear the stored API key from Secret Service."""
        try:
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            schema = Secret.Schema.new(
                SECRET_SCHEMA_NAME,
                Secret.SchemaFlags.NONE,
                {"service": Secret.SchemaAttributeType.STRING},
            )
            Secret.password_clear_sync(schema, dict(SECRET_ATTRIBUTES), None)
        except Exception as exc:
            raise SecretStorageError("Failed to clear API key in Secret Service") from exc
