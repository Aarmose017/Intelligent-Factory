"""The alert contract with Team B, written from schema/sample_alert.json and docs/definitions.md.

An alert missing one of these fields, or with the wrong type, is rejected and logged. Fields not listed here,
like observed_deviation, are let through untouched, so Team B can add detail without breaking us.
An unknown incident_class is not a schema error: it is logged as no rule matched, which is still a team decision.
"""
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _utc_iso(s):
    # ISO 8601 with a timezone, so all four timestamps in a log line can be compared.
    if datetime.fromisoformat(s).tzinfo is None:
        raise ValueError("timestamp needs a timezone, for example 2026-10-01T14:22:31Z")
    return s  # kept as the string Team B sent, so the log shows exactly what arrived


Text = Annotated[str, Field(strict=True, min_length=1)]
Timestamp = Annotated[str, Field(strict=True), AfterValidator(_utc_iso)]


class Alert(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal["1.0"]
    alert_id: Text
    emitted_at: Timestamp
    observed_at: Timestamp
    incident_class: Text
    confidence: Annotated[float, Field(strict=True, ge=0, le=1)]  # strict: no "0.8" strings, no true/false
    affected_subsystem: Text
