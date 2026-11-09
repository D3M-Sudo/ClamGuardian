"""Fail-closed OS Secret Service storage for separate VirusTotal profiles."""
from __future__ import annotations

from .profiles import APIProfile, profile_secret_attribute

SECRET_SCHEMA_NAME = "io.github.clamguardian.ThreatIntelligence"
SECRET_LABEL = "ClamGuardian VirusTotal API Credential"


class SecretStorageError(RuntimeError):
    """Raised when Secret Service is unavailable or fails."""


class IntelligenceSecretStore:
    """Store Public and Premium credentials independently in Secret Service."""

    @staticmethod
    def _secret_api():
        try:
            import gi
            gi.require_version("Secret", "1")
            from gi.repository import Secret
            return Secret
        except Exception as exc:
            raise SecretStorageError(
                "Secure credential storage (Secret Service / libsecret) is unavailable. "
                "Plaintext credential storage is prohibited."
            ) from exc

    @classmethod
    def _schema(cls, Secret):
        return Secret.Schema.new(
            SECRET_SCHEMA_NAME,
            Secret.SchemaFlags.NONE,
            {"service": Secret.SchemaAttributeType.STRING},
        )

    @staticmethod
    def _attributes(profile: APIProfile | str) -> dict[str, str]:
        return {"service": profile_secret_attribute(profile)}

    @classmethod
    def is_available(cls) -> bool:
        try:
            Secret = cls._secret_api()
            Secret.password_lookup_sync(
                cls._schema(Secret), cls._attributes(APIProfile.PUBLIC), None
            )
            return True
        except Exception:
            return False

    def get_credential(self, profile: APIProfile | str) -> str | None:
        Secret = self._secret_api()
        try:
            value = Secret.password_lookup_sync(
                self._schema(Secret), self._attributes(profile), None
            )
            if not value and APIProfile.parse(profile) is APIProfile.PUBLIC:
                # Migrate credentials written by the pre-dual-profile release.
                value = Secret.password_lookup_sync(
                    self._schema(Secret), {"service": "virustotal-api-key"}, None
                )
                if value:
                    self.set_credential(APIProfile.PUBLIC, value)
            return value or None
        except Exception as exc:
            raise SecretStorageError("Could not retrieve VirusTotal credential from Secret Service") from exc

    def set_credential(self, profile: APIProfile | str, api_key: str) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("API key cannot be empty")
        Secret = self._secret_api()
        try:
            ok = Secret.password_store_sync(
                self._schema(Secret),
                self._attributes(profile),
                Secret.COLLECTION_DEFAULT,
                f"{SECRET_LABEL} ({APIProfile.parse(profile).value})",
                api_key.strip(),
                None,
            )
            if not ok:
                raise SecretStorageError("Secret Service refused to store the credential")
        except SecretStorageError:
            raise
        except Exception as exc:
            raise SecretStorageError("Could not store VirusTotal credential in Secret Service") from exc

    def clear_credential(self, profile: APIProfile | str) -> None:
        Secret = self._secret_api()
        try:
            Secret.password_clear_sync(
                self._schema(Secret), self._attributes(profile), None
            )
        except Exception as exc:
            raise SecretStorageError("Could not clear VirusTotal credential from Secret Service") from exc

    # Backwards-compatible Public profile methods.
    def get_api_key(self) -> str | None:
        return self.get_credential(APIProfile.PUBLIC)

    def set_api_key(self, api_key: str) -> None:
        self.set_credential(APIProfile.PUBLIC, api_key)

    def clear_api_key(self) -> None:
        self.clear_credential(APIProfile.PUBLIC)
