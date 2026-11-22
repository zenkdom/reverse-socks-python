"""
User Manager for SOCKS5 Client Authentication.
Persists users to users.json and provides thread/async-safe management.
"""
from __future__ import annotations

import json
import os
import time
import asyncio
import logging

logger = logging.getLogger("UserManager")


class UserManager:
    """Manages credentials for SOCKS5 clients."""

    def __init__(self, filepath: str = "users.json"):
        # Resolve absolute or relative path
        if not os.path.isabs(filepath):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.filepath = os.path.join(base_dir, filepath)
        else:
            self.filepath = filepath

        self.users: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.load()

    def load(self):
        """Load users from JSON file."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.users = {u["username"]: u for u in data.get("users", [])}
                    logger.info(f"Loaded {len(self.users)} SOCKS5 user(s) from {self.filepath}")
            except Exception as e:
                logger.error(f"Failed to load {self.filepath}: {e}")
                self.users = {}
        else:
            logger.info(f"Users file {self.filepath} not found, initializing empty store.")
            self.save_sync()

    def save_sync(self):
        """Save users to JSON file synchronously."""
        try:
            temp_path = f"{self.filepath}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump({"users": list(self.users.values())}, f, indent=2, ensure_ascii=False)
            if os.path.exists(self.filepath):
                os.replace(temp_path, self.filepath)
            else:
                os.rename(temp_path, self.filepath)
        except Exception as e:
            logger.error(f"Failed to save {self.filepath}: {e}")

    async def add_user(self, username: str, password: str) -> tuple[bool, str]:
        """Add a new SOCKS5 user."""
        username = username.strip()
        password = password.strip()
        if not username:
            return False, "Username cannot be empty"
        if not password:
            return False, "Password cannot be empty"

        async with self._lock:
            if username in self.users:
                return False, f"User '{username}' already exists"

            self.users[username] = {
                "username": username,
                "password": password,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.save_sync()
            logger.info(f"Added SOCKS5 user '{username}'")
            return True, f"User '{username}' added successfully"

    async def delete_user(self, username: str) -> tuple[bool, str]:
        """Delete an existing SOCKS5 user."""
        username = username.strip()
        async with self._lock:
            if username not in self.users:
                return False, f"User '{username}' not found"

            del self.users[username]
            self.save_sync()
            logger.info(f"Deleted SOCKS5 user '{username}'")
            return True, f"User '{username}' deleted successfully"

    def authenticate(self, username: str, password: str) -> bool:
        """Validate SOCKS5 username and password."""
        user = self.users.get(username)
        if not user:
            return False
        return user.get("password") == password

    def has_user(self, username: str) -> bool:
        """Check if username exists in users database."""
        return username in self.users

    def get_all_users(self) -> list[dict]:
        """Return list of all users."""
        return list(self.users.values())

    def get_user_count(self) -> int:
        return len(self.users)
