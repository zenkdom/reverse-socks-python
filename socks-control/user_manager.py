"""
Re-export UserManager from socks_users for backwards compatibility.
"""
import sys
import os

# Ensure local directory is in path
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from socks_users import UserManager

__all__ = ["UserManager"]
