"""
User / Client Manager for MTProto Proxy.
Manages MTProto clients and their secret keys.
Persists data to mtproto_users.json and provides thread/async-safe management.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from typing import Optional

logger = logging.getLogger("MtprotoUserManager")


def normalize_hex_secret(secret_str: str, domain: str = "google.com") -> tuple[str, str, str]:
    """
    Normalizes secret:
    - If empty, generates a random 16-byte (32 hex) secret.
    - If 32 hex chars, validates and constructs 'ee' + secret + domain_hex.
    - If starts with 'ee', extracts the 32 hex chars secret and domain.
    Returns (raw_secret_hex, domain, fake_tls_secret).
    """
    cleaned = secret_str.strip().lower()
    if not cleaned:
        raw_hex = secrets.token_hex(16)
        domain_hex = domain.encode("utf-8").hex()
        return raw_hex, domain, f"ee{raw_hex}{domain_hex}"

    if cleaned.startswith("ee") and len(cleaned) > 34:
        raw_hex = cleaned[2:34]
        domain_hex = cleaned[34:]
        try:
            extracted_domain = bytes.fromhex(domain_hex).decode("utf-8", errors="ignore")
            if extracted_domain:
                domain = extracted_domain
        except Exception:
            pass
        return raw_hex, domain, cleaned

    # Strip any non-hex characters
    raw_hex = re.sub(r"[^0-9a-fA-F]", "", cleaned).lower()
    if len(raw_hex) < 32:
        raw_hex = raw_hex.zfill(32)
    elif len(raw_hex) > 32:
        raw_hex = raw_hex[:32]

    domain_hex = domain.encode("utf-8").hex()
    fake_tls_secret = f"ee{raw_hex}{domain_hex}"
    return raw_hex, domain, fake_tls_secret


def normalize_tag(tag_str: Optional[str]) -> Optional[str]:
    """
    Normalizes promo tag from @MTProxybot:
    - Strips whitespace.
    - Ensures valid 32 hex characters (16 bytes).
    Returns normalized 32-char hex string, or None if empty or invalid.
    """
    if not tag_str:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", str(tag_str).strip()).lower()
    if len(cleaned) == 32:
        return cleaned
    return None


class MtprotoUserManager:
    """Manages credentials, secret keys, and promo tags for MTProto clients."""

    def __init__(
        self,
        filepath: str = "mtproto_users.json",
        default_secret: Optional[str] = None,
        default_domain: str = "google.com",
        default_tag: Optional[str] = None,
    ):
        if not os.path.isabs(filepath):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.join(base_dir, filepath)
            if os.path.exists(filepath):
                self.filepath = os.path.abspath(filepath)
            elif os.path.exists(candidate) or not os.path.dirname(filepath):
                self.filepath = candidate
            else:
                self.filepath = os.path.abspath(filepath)
        else:
            self.filepath = filepath

        self.default_secret = default_secret
        self.default_domain = default_domain
        self.default_tag = normalize_tag(default_tag)
        self.clients: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.load()

    def load(self):
        """Load clients from mtproto_users.json."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.clients = {c["client_name"]: c for c in data.get("clients", [])}
                    for c in self.clients.values():
                        c.setdefault("tag", None)
                    logger.info(f"Loaded {len(self.clients)} MTProto client(s) from {self.filepath}")
            except Exception as e:
                logger.error(f"Failed to load {self.filepath}: {e}")
                self.clients = {}

        # If file is empty or missing, initialize with default client
        if not self.clients and self.default_secret:
            raw_hex, domain, fake_tls = normalize_hex_secret(self.default_secret, self.default_domain)
            default_client = {
                "client_name": "default",
                "secret": raw_hex,
                "domain": domain,
                "fake_tls_secret": fake_tls,
                "tag": self.default_tag,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.clients["default"] = default_client
            self.save_sync()
            logger.info(f"Initialized mtproto_users.json with default client (TAG: {self.default_tag}).")
        elif "default" in self.clients and not self.clients["default"].get("tag") and self.default_tag:
            self.clients["default"]["tag"] = self.default_tag
            self.save_sync()

    def save_sync(self):
        """Save clients to mtproto_users.json atomically."""
        try:
            parent_dir = os.path.dirname(self.filepath)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            temp_path = f"{self.filepath}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump({"clients": list(self.clients.values())}, f, indent=2, ensure_ascii=False)
            if os.path.exists(self.filepath):
                os.replace(temp_path, self.filepath)
            else:
                os.rename(temp_path, self.filepath)
        except Exception as e:
            logger.error(f"Failed to save {self.filepath}: {e}")

    async def add_client(
        self,
        client_name: str,
        secret: Optional[str] = None,
        domain: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> tuple[bool, str, Optional[dict]]:
        """
        Add a new MTProto client.
        If secret is empty, generates a secure random 32-hex secret.
        Optionally associates a 32-hex promo TAG from @MTProxybot.
        """
        client_name = client_name.strip()
        if not client_name:
            return False, "MTProto client name cannot be empty", None

        # Disallow problematic characters
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", client_name):
            return False, "Client name can only contain alphanumeric characters, hyphens, dots, and underscores", None

        dom = (domain or self.default_domain).strip().lower()
        raw_hex, dom, fake_tls = normalize_hex_secret(secret or "", dom)

        # Validate tag if provided
        tag_clean = None
        if tag and tag.strip():
            tag_clean = normalize_tag(tag)
            if not tag_clean:
                return False, "Promo channel TAG must be exactly 32 hex characters from @MTProxybot", None

        async with self._lock:
            if client_name in self.clients:
                return False, f"MTProto client '{client_name}' already exists", None

            # Check if secret already used by another client
            for c in self.clients.values():
                if c.get("secret") == raw_hex:
                    return False, f"Secret key is already used by client '{c['client_name']}'", None

            new_client = {
                "client_name": client_name,
                "secret": raw_hex,
                "domain": dom,
                "fake_tls_secret": fake_tls,
                "tag": tag_clean,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.clients[client_name] = new_client
            self.save_sync()
            logger.info(f"Added MTProto client '{client_name}' (Fake-TLS: {fake_tls[:15]}..., TAG: {tag_clean})")
            return True, f"MTProto client '{client_name}' created successfully!", new_client

    async def update_client_tag(self, client_name: str, tag: Optional[str]) -> tuple[bool, str]:
        """Update or clear promo TAG for an existing MTProto client configuration."""
        client_name = client_name.strip()
        tag_str = (tag or "").strip()
        tag_clean = None
        if tag_str:
            tag_clean = normalize_tag(tag_str)
            if not tag_clean:
                return False, "Invalid format: TAG must be exactly 32 hex characters (from @MTProxybot)"

        async with self._lock:
            if client_name not in self.clients:
                return False, f"MTProto client configuration for '{client_name}' not found"

            self.clients[client_name]["tag"] = tag_clean
            self.save_sync()
            msg = f"Promo TAG for '{client_name}' saved successfully!" if tag_clean else f"Promo TAG for '{client_name}' removed"
            logger.info(f"Updated TAG for MTProto client '{client_name}': {tag_clean}")
            return True, msg

    def get_client(self, client_name: str) -> Optional[dict]:
        """Return dict for given MTProto client if found."""
        return self.clients.get(client_name)

    def get_tag_for_user(self, client_name: str) -> Optional[str]:
        """Return promo TAG assigned to given client."""
        client = self.clients.get(client_name)
        if client:
            return client.get("tag")
        return None

    async def delete_client(self, client_name: str) -> tuple[bool, str]:
        """Delete an existing MTProto client."""
        client_name = client_name.strip()
        async with self._lock:
            if client_name not in self.clients:
                return False, f"MTProto client '{client_name}' not found"

            if len(self.clients) <= 1:
                return False, "Cannot delete the last MTProto client (at least one active key must remain)"

            del self.clients[client_name]
            self.save_sync()
            logger.info(f"Deleted MTProto client '{client_name}'")
            return True, f"MTProto client '{client_name}' deleted successfully"

    def get_all_clients(self) -> list[dict]:
        """Return list of all registered MTProto clients."""
        return list(self.clients.values())

    def get_secrets_map(self) -> dict[str, bytes]:
        """Return mapping of client_name -> raw_secret_bytes for cipher validation."""
        res = {}
        for c in self.clients.values():
            try:
                res[c["client_name"]] = bytes.fromhex(c["secret"])
            except Exception:
                pass
        return res
