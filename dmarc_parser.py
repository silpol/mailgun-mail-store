"""
dmarc_parser.py — stdlib-only DMARC report parser (replacement for parsedmarc).

The app needs exactly one call from parsedmarc, and about a dozen fields of its
output. This module provides the same call shape and the same output contract
(docs/PLAN_drop_parsedmarc.md section 2) without the ~30 transitive packages.

    parse_report_file(path, offline=True) -> dict | list[dict]

Each dict is {"report_type": "aggregate" | "failure", "report": {...}}.
A container with several reports (multi-member zip) returns a list.
Anything that is not a recognisable report raises ParserError, so the app's
except-branch quarantines the file to failed/ exactly as with parsedmarc.

Safety (reports are attacker-controlled input: anyone can send mail to the
rua= address):
  * XML with a DOCTYPE or ENTITY declaration is rejected before parsing
    (real reports never carry one; fixes entity / default-attribute
    amplification, cf. parsedmarc GHSA-m47j-wp78-fqjg)
  * decompressed size is capped (zip/gzip bombs)
"""
import datetime
import email
import email.policy
import email.utils
import gzip
import io
import re
import zipfile
import xml.etree.ElementTree as ET

__all__ = ["parse_report_file", "ParserError", "MAX_DECOMPRESSED_BYTES"]

# Largest real aggregate reports are a few MB uncompressed; 50 MB is generous.
MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")  # local file header / empty archive
_GZIP_MAGIC = b"\x1f\x8b"
_DTD_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class ParserError(ValueError):
    """The input is not a DMARC report this parser can read."""


# ---------------------------------------------------------------- containers

def _read_capped(stream):
    data = stream.read(MAX_DECOMPRESSED_BYTES + 1)
    if len(data) > MAX_DECOMPRESSED_BYTES:
        raise ParserError(f"decompressed report exceeds {MAX_DECOMPRESSED_BYTES} bytes")
    return data


def _unpack(content):
    """Yield the payload(s) inside a zip / gzip container, or the bytes as-is."""
    if content.startswith(_ZIP_MAGICS):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                members = [i for i in z.infolist() if not i.is_dir()]
                if not members:
                    raise ParserError("zip archive is empty")
                total = 0
                for info in members:
                    with z.open(info) as f:
                        data = _read_capped(f)
                    total += len(data)
                    if total > MAX_DECOMPRESSED_BYTES:
                        raise ParserError("zip contents exceed the size cap")
                    yield data
        except zipfile.BadZipFile as exc:
            raise ParserError(f"bad zip archive: {exc}") from exc
    elif content.startswith(_GZIP_MAGIC):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as g:
                yield _read_capped(g)
        except (OSError, EOFError) as exc:
            raise ParserError(f"bad gzip data: {exc}") from exc
    else:
        yield content


# ---------------------------------------------------------------- XML helpers

def _strip_ns(root):
    """Drop XML namespaces (RFC 9990 reports use urn:ietf:params:xml:ns:dmarc-2.0)."""
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{"):
            el.tag = el.tag.split("}", 1)[1]
    return root


def _safe_xml(data):
    if _DTD_RE.search(data):
        raise ParserError("XML with DOCTYPE/ENTITY declarations is rejected")
    try:
        return _strip_ns(ET.fromstring(data))
    except ET.ParseError as exc:
        raise ParserError(f"invalid XML: {exc}") from exc


def _text(el, path, default=None):
    found = el.find(path) if el is not None else None
    if found is None or found.text is None:
        return default
    value = found.text.strip()
    return value if value != "" else default


def _lower(value):
    return value.lower() if isinstance(value, str) else value


def _epoch_to_utc_str(value):
    """parsedmarc's date format: 'YYYY-MM-DD HH:MM:SS' in UTC."""
    if value is None:
        return None
    try:
        ts = int(float(value))
    except ValueError:
        return value
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- aggregate

def _parse_record(rec):
    row = rec.find("row")
    source_ip = _text(row, "source_ip")
    if source_ip is None:
        raise ParserError("aggregate record without source_ip")
    count_text = _text(row, "count", "0")
    try:
        count = int(count_text)
    except ValueError as exc:
        raise ParserError(f"bad record count: {count_text!r}") from exc

    pe = row.find("policy_evaluated") if row is not None else None
    # Same defaults as parsedmarc: a missing result counts as "fail".
    policy_evaluated = {
        "disposition": _lower(_text(pe, "disposition", "none")),
        "dkim": _lower(_text(pe, "dkim", "fail")),
        "spf": _lower(_text(pe, "spf", "fail")),
        "policy_override_reasons": [
            {"type": _lower(_text(r, "type")), "comment": _text(r, "comment")}
            for r in (pe.findall("reason") if pe is not None else [])
        ],
    }

    ids = rec.find("identifiers")
    header_from = _text(ids, "header_from")
    identifiers = {
        "header_from": header_from.lower() if header_from else header_from,
        "envelope_from": _text(ids, "envelope_from"),
        "envelope_to": _text(ids, "envelope_to"),
    }

    ar = rec.find("auth_results")
    auth_results = {
        "dkim": [
            {"domain": _text(d, "domain"), "selector": _text(d, "selector"),
             "result": _lower(_text(d, "result"))}
            for d in (ar.findall("dkim") if ar is not None else [])
        ],
        "spf": [
            {"domain": _text(s, "domain"), "scope": _lower(_text(s, "scope")),
             "result": _lower(_text(s, "result"))}
            for s in (ar.findall("spf") if ar is not None else [])
        ],
    }

    return {
        "source": {"ip_address": source_ip},
        "count": count,
        "alignment": {
            "spf": policy_evaluated["spf"] == "pass",
            "dkim": policy_evaluated["dkim"] == "pass",
            "dmarc": "pass" in (policy_evaluated["spf"], policy_evaluated["dkim"]),
        },
        "policy_evaluated": policy_evaluated,
        "identifiers": identifiers,
        "auth_results": auth_results,
    }


def _parse_aggregate(root):
    meta = root.find("report_metadata")
    pp = root.find("policy_published")
    if meta is None or pp is None:
        raise ParserError("not an aggregate report (missing report_metadata/policy_published)")
    begin = _epoch_to_utc_str(_text(meta, "date_range/begin"))
    end = _epoch_to_utc_str(_text(meta, "date_range/end"))
    return {
        "xml_schema": _text(root, "version", "draft"),
        "report_metadata": {
            "org_name": _text(meta, "org_name"),
            "org_email": _text(meta, "email"),
            "report_id": _text(meta, "report_id"),
            "begin_date": begin,
            "end_date": end,
        },
        "policy_published": {
            "domain": _text(pp, "domain"),  # case kept as sent (parsedmarc does too)
            "adkim": _lower(_text(pp, "adkim", "r")),
            "aspf": _lower(_text(pp, "aspf", "r")),
            "p": _lower(_text(pp, "p")),
            "sp": _lower(_text(pp, "sp")),
            "pct": _text(pp, "pct"),
            "fo": _text(pp, "fo"),
        },
        "records": [_parse_record(r) for r in root.findall("record")],
    }


# ---------------------------------------------------------------- failure (RUF)

def _feedback_fields(part):
    """Header-style fields of a message/feedback-report part (RFC 5965)."""
    payload = part.get_payload()
    if isinstance(payload, list) and payload:
        # The email package parses message/* parts into Message objects; a
        # feedback report may come back as one or several header blocks.
        fields = {}
        for block in payload:
            for k, v in block.items():
                fields.setdefault(k.lower(), str(v))
        return fields
    text = part.get_content() if hasattr(part, "get_content") else str(payload)
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    headers = email.message_from_string(text.lstrip(), policy=email.policy.default)
    return {k.lower(): str(v) for k, v in headers.items()}


def _utc_str(date_header):
    if not date_header:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        return date_header
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_email(content):
    msg = email.message_from_bytes(content, policy=email.policy.default)
    feedback = None
    attachments = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/feedback-report":
            feedback = part
        elif ctype in ("application/zip", "application/gzip", "application/x-gzip",
                       "text/xml", "application/xml", "application/octet-stream"):
            data = part.get_payload(decode=True)
            if data:
                attachments.append(data)

    if feedback is not None:
        f = _feedback_fields(feedback)
        auth = [a.strip().lower() for a in f.get("auth-failure", "").split(",") if a.strip()]
        arrival = f.get("arrival-date") or f.get("received-date") or msg.get("Date")
        return [{"report_type": "failure", "report": {
            "feedback_type": _lower(f.get("feedback-type")),
            "reported_domain": _lower(f.get("reported-domain")),
            "arrival_date": arrival,
            "arrival_date_utc": _utc_str(arrival),
            "auth_failure": auth,
            "source": {"ip_address": f.get("source-ip")},
            "delivery_result": _lower(f.get("delivery-result")),
            "original_mail_from": f.get("original-mail-from"),
            "original_rcpt_to": f.get("original-rcpt-to"),
        }}]

    # An aggregate report delivered as a whole email (attachment inside).
    reports = []
    for data in attachments:
        reports.extend(_parse_content(data, allow_email=False))
    if reports:
        return reports
    raise ParserError("email contains neither a feedback report nor an aggregate attachment")


# ---------------------------------------------------------------- entry point

def _looks_like_email(data):
    head = data[:4096].lower()
    return b"\nfrom:" in b"\n" + head or b"content-type:" in head or b"mime-version:" in head


def _parse_content(content, allow_email=True):
    reports = []
    for blob in _unpack(content):
        stripped = blob.lstrip()
        if stripped.startswith(b"<"):
            root = _safe_xml(stripped)
            if root.tag != "feedback":
                raise ParserError(f"unexpected XML root <{root.tag}>")
            reports.append({"report_type": "aggregate", "report": _parse_aggregate(root)})
        elif stripped.startswith(_ZIP_MAGICS) or stripped.startswith(_GZIP_MAGIC):
            reports.extend(_parse_content(stripped, allow_email=allow_email))
        elif allow_email and _looks_like_email(stripped):
            reports.extend(_parse_email(stripped))
        else:
            raise ParserError("not a DMARC report (no XML, archive or email found)")
    if not reports:
        raise ParserError("no report found")
    return reports


def parse_report_file(path, offline=True):
    """Parse a DMARC report file. ``offline`` is accepted for parsedmarc call
    compatibility and ignored: this parser never makes network calls."""
    with open(path, "rb") as f:
        content = f.read()
    if not content:
        raise ParserError("empty file")
    reports = _parse_content(content)
    return reports[0] if len(reports) == 1 else reports
