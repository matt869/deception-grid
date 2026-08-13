"""Deception assets: host personas, banners and non-executing fake responses."""

from honeypot.deception.banners import PERSONAS, Persona, get_persona, list_personas
from honeypot.deception.responses import FakeShell, http_response_for

__all__ = ["Persona", "PERSONAS", "get_persona", "list_personas", "FakeShell", "http_response_for"]
