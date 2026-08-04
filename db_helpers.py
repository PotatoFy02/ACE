# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE — Automated Cybersecurity Engine
# Generic Supabase wrapper. Type-safety written once, used everywhere.
from typing import TypeVar, Type, Any
from pydantic import BaseModel, ValidationError
import logging
from supabase import create_client, Client

log = logging.getLogger("db_helpers")

T = TypeVar("T", bound=BaseModel)


def make_client(url: str, key: str, jwt: str | None = None) -> Client:
    """Create a Supabase client, optionally scoped to a user JWT."""
    c = create_client(url, key)
    if jwt:
        c.postgrest.auth(jwt)
    return c


def parse_rows(data: Any, model: Type[T]) -> list[T]:
    """
    Safely converts raw Supabase JSON list into typed Pydantic models.
    Invalid rows are logged and skipped — never crashes the pipeline.
    Written once, used everywhere.
    """
    if data is None or not isinstance(data, list):
        return []
    results: list[T] = []
    for row in data:
        if not isinstance(row, dict):
            log.warning("Skipping non-dict row: %r", row)
            continue
        try:
            results.append(model.model_validate(row))
        except ValidationError as e:
            log.warning("Row failed validation (id=%s): %s", row.get("id", "?"), e)
    return results


def parse_row(data: Any, model: Type[T]) -> T | None:
    """Single row variant of parse_rows."""
    if data is None or not isinstance(data, dict):
        return None
    try:
        return model.model_validate(data)
    except ValidationError as e:
        log.warning("Row failed validation: %s", e)
        return None


def safe_id(data: Any) -> str:
    """Safely extract id from a Supabase insert response."""
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return str(data[0].get("id", ""))
    if isinstance(data, dict):
        return str(data.get("id", ""))
    return ""
