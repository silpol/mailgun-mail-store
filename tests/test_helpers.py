"""Unit tests for the _safe_get and _format_report_date helpers in app.py."""
import datetime

import pytest

from app import _format_report_date, _safe_get


# ---------------------------------------------------------------------------
# _safe_get
# ---------------------------------------------------------------------------

class TestSafeGet:
    """Tests for the _safe_get nested-dict accessor."""

    def test_single_key_present(self):
        assert _safe_get({"a": 1}, "a") == 1

    def test_nested_keys_present(self):
        assert _safe_get({"a": {"b": {"c": 42}}}, "a", "b", "c") == 42

    def test_missing_key_returns_default(self):
        assert _safe_get({"a": 1}, "b") is None

    def test_missing_nested_key_returns_default(self):
        assert _safe_get({"a": {"b": 1}}, "a", "c") is None

    def test_custom_default_returned_on_miss(self):
        assert _safe_get({}, "x", default="fallback") == "fallback"

    def test_intermediate_non_dict_returns_default(self):
        # "b" is an int, not a dict — traversal should stop safely.
        assert _safe_get({"a": {"b": 5}}, "a", "b", "c") is None

    def test_value_none_returns_default(self):
        # Stored value is None → should return the default.
        assert _safe_get({"a": None}, "a", default="nope") == "nope"

    def test_empty_dict_returns_default(self):
        assert _safe_get({}, "x", "y", default=0) == 0

    def test_falsy_non_none_value_returned(self):
        # 0 and False are falsy but valid non-None values.
        assert _safe_get({"a": 0}, "a", default=-1) == 0
        assert _safe_get({"a": False}, "a", default=True) is False

    def test_value_is_empty_string(self):
        assert _safe_get({"a": ""}, "a", default="x") == ""


# ---------------------------------------------------------------------------
# _format_report_date
# ---------------------------------------------------------------------------

class TestFormatReportDate:
    """Tests for the _format_report_date date formatter."""

    def test_none_returns_unknown(self):
        assert _format_report_date(None) == "unknown"

    def test_empty_string_returns_unknown(self):
        assert _format_report_date("") == "unknown"

    def test_zero_epoch_is_not_unknown(self):
        # Epoch 0 is a valid timestamp (1970-01-01T00:00:00Z).
        result = _format_report_date(0)
        assert result != "unknown"
        assert "1970" in result

    def test_integer_epoch_returns_iso_z(self):
        # Unix epoch 1609459200 = 2021-01-01T00:00:00Z
        result = _format_report_date(1609459200)
        assert result == "2021-01-01T00:00:00Z"

    def test_float_epoch_returns_iso_z(self):
        result = _format_report_date(1609459200.0)
        assert result == "2021-01-01T00:00:00Z"

    def test_datetime_with_utc_timezone(self):
        dt = datetime.datetime(2021, 6, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
        result = _format_report_date(dt)
        assert result == "2021-06-15T12:00:00Z"

    def test_datetime_without_timezone_assumed_utc(self):
        dt = datetime.datetime(2021, 6, 15, 12, 0, 0)  # no tzinfo
        result = _format_report_date(dt)
        assert result == "2021-06-15T12:00:00Z"

    def test_string_returned_as_is(self):
        assert _format_report_date("some-date-string") == "some-date-string"

    def test_arbitrary_object_returns_str(self):
        class Obj:
            def __str__(self):
                return "custom"

        assert _format_report_date(Obj()) == "custom"
