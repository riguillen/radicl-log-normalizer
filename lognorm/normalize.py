import json
import re

from datetime import datetime, timedelta, timezone

from enum import StrEnum
from typing import NamedTuple

class LogLevel(StrEnum):
    EMERGENCY = "emergency"
    ALERT     = "alert"
    CRITICAL  = "critical"
    ERROR     = "error"
    WARNING   = "warning"
    NOTICE    = "notice"
    INFO      = "info"
    DEBUG     = "debug"


# Syslog PRI severity (RFC 5424 s6.2.1): severity = PRI % 8
LEVEL_BY_SEVERITY: dict[int, LogLevel] = {
    0: LogLevel.EMERGENCY,
    1: LogLevel.ALERT,
    2: LogLevel.CRITICAL,
    3: LogLevel.ERROR,
    4: LogLevel.WARNING,
    5: LogLevel.NOTICE,
    6: LogLevel.INFO,
    7: LogLevel.DEBUG,
}

LEVEL_BY_WINDOWS_NAME: dict[str, LogLevel] = {
    "critical":      LogLevel.CRITICAL,
    "error":         LogLevel.ERROR,
    "warning":       LogLevel.WARNING,
    "information":   LogLevel.INFO,
    "informational": LogLevel.INFO,
    "verbose":       LogLevel.DEBUG,
    "logalways":     LogLevel.INFO,
}

def level_from_windows(name) -> LogLevel:
    if not isinstance(name, str):
        return LogLevel.INFO
    return LEVEL_BY_WINDOWS_NAME.get(name.strip().lower(), LogLevel.INFO)

class EventType(StrEnum):
    START = "start"; END = "end"; INFO = "info"
    DENIED = "denied"; ALLOWED = "allowed"

class Category(StrEnum):
    AUTHENTICATION = "authentication"; NETWORK = "network"
    PROCESS = "process"; HOST = "host"


class EventMeta(NamedTuple):
    type: EventType
    category: Category

EVENT_BY_ID: dict[int, EventMeta] = {
    4624: EventMeta(EventType.START, Category.AUTHENTICATION),
    4625: EventMeta(EventType.START, Category.AUTHENTICATION),
    4634: EventMeta(EventType.END,   Category.AUTHENTICATION),
    4647: EventMeta(EventType.END,   Category.AUTHENTICATION),
    4648: EventMeta(EventType.START, Category.AUTHENTICATION),
    4688: EventMeta(EventType.START, Category.PROCESS),
    4689: EventMeta(EventType.END,   Category.PROCESS),
}

DEFAULT = EventMeta(EventType.INFO, Category.HOST)

SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<msg>.*)$"
)

CEF_KEY_RE = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=")

def parse_cef_extensions(ext: str) -> dict:
    out, matches = {}, list(CEF_KEY_RE.finditer(ext))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(ext)
        out[m.group(1)] = ext[m.end():end].strip()
    return out

def iso8601(value: str) -> str:
    """JSON path: parse an ISO 8601 string (e.g. System.TimeCreated)."""
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return format_utc(datetime.now(timezone.utc))   # missing or malformed: fall back to now
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)            # no offset given: treat as UTC
    return format_utc(dt)

def detect(line: str) -> str:
    """Per-line format detection: '{' means JSON, anything else is syslog."""
    return "json" if line.lstrip().startswith("{") else "syslog"

def parse_syslog(line: str) -> dict:
    m = SYSLOG_RE.match(line.strip())
    if m is None:
        raise ValueError("not a valid RFC 3164 syslog line")
    pri = int(m.group("pri"))
    result = {
        "pri": pri,
        "facility": pri // 8,
        "severity": pri % 8,
        "timestamp": m.group("ts"),
        "hostname": m.group("host"),
        "cef": None,
        "extensions": {},
        "raw": line.strip(),
    }
    
    msg = m.group("msg")          # <- step 2 starts here
    if msg.startswith("CEF:"):
        parts = msg[4:].split("|", 7) # strip "CEF:", 7 splits -> 8 pieces
        if len(parts) == 8:
            keys = ["version", "vendor", "product", "device_version",
                    "signature_id", "name", "severity"]
            result["cef"] = dict(zip(keys, parts[:7]))
            result["extensions"] = parse_cef_extensions(parts[7])   # <- step 3
        else:
            result["message"] = msg     # looked like CEF but isn't well-formed
    else:
        result["message"] = msg
        
    return format_syslog(result)

def format_utc(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def syslog_timestamp(ts: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return format_utc(now)          # spec: use current UTC if parsing fails
    if dt > now + timedelta(days=1):    # no year in RFC 3164; don't produce future dates
        dt = dt.replace(year=dt.year - 1)
    return format_utc(dt)

ALLOW_ACTIONS = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass"}
DENY_ACTIONS  = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected"}

AUTH_END_WORDS   = ("logoff", "logged off", "log off", "logout", "logged out")
AUTH_START_WORDS = ("logon", "logged on", "log on", "login", "logged in")

def syslog_event_type(parsed: dict) -> EventType:
    ext = parsed.get("extensions") or {}
    cef = parsed.get("cef") or {}

    # Rules 1-2: the CEF act= field
    act = (ext.get("act") or "").strip().lower()
    if act in ALLOW_ACTIONS:
        return EventType.ALLOWED
    if act in DENY_ACTIONS:
        return EventType.DENIED

    # Rule 3: auth-related text
    text = " ".join(filter(None, [ext.get("msg"), cef.get("name"), parsed.get("message")])).lower()
    if any(w in text for w in AUTH_END_WORDS):
        return EventType.END
    if any(w in text for w in AUTH_START_WORDS):
        return EventType.START

    # Rule 4: everything else
    return EventType.INFO

CATEGORY_KEYWORDS = [   # checked in order, first match wins
    (Category.AUTHENTICATION, AUTH_START_WORDS + AUTH_END_WORDS + ("auth",)),
    (Category.NETWORK,        ("connection", "traffic")),
]


def syslog_event_category(parsed: dict) -> str:
    ext = parsed.get("extensions") or {}
    cef = parsed.get("cef") or {}

    cef_class = (cef.get("signature_id") or "").strip().lower()
    if cef_class == "authentication":
        return "authentication"
    if cef_class == "traffic":
        return "network"

    text = " ".join(filter(None, [ext.get("msg"), cef.get("name"), parsed.get("message")])).lower()
    for category, words in CATEGORY_KEYWORDS:
        if any(w in text for w in words):
            return category.value

    # Rule 3: everything else
    return "host"

class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

FAILURE_WORDS = ("unsuccessful", "failure", "failed", "deny", "denied", "block", "reject")
SUCCESS_WORDS = ("success", "allow", "accept", "permit")


def syslog_outcome(parsed: dict) -> Outcome:
    ext = parsed.get("extensions") or {}
    cef = parsed.get("cef") or {}

    # Rule 1: the CEF outcome= extension, when the device gives it directly
    explicit = (ext.get("outcome") or "").strip().lower()
    if explicit in (Outcome.SUCCESS, Outcome.FAILURE):
        return Outcome(explicit)

    # Rule 2: search the message text and all extension values
    text = " ".join(filter(None, [ext.get("msg"), cef.get("name"), parsed.get("message"), *ext.values()])).lower()
    if any(w in text for w in FAILURE_WORDS):
        return Outcome.FAILURE
    if any(w in text for w in SUCCESS_WORDS):
        return Outcome.SUCCESS

    # Rule 3: everything else
    return Outcome.UNKNOWN

def format_syslog(parsed: dict) -> dict:
    ext = parsed.get("extensions") or {}
    cef = parsed.get("cef") or {}
    final_dict={}
    final_dict["@timestamp"] = syslog_timestamp(parsed.get("timestamp"))
    final_dict["event.type"] = syslog_event_type(parsed).value
    final_dict["event.category"] = syslog_event_category(parsed)
    final_dict["event.outcome"] = syslog_outcome(parsed).value
    final_dict["source.ip"] = clean(ext.get("src"))
    final_dict["user.name"] = clean(ext.get("suser"))
    final_dict["host.name"] = clean(parsed.get("hostname"))
    final_dict["log.level"] = LEVEL_BY_SEVERITY.get(parsed.get("severity"), LogLevel.INFO).value
    final_dict["message"] = (
        clean(ext.get("msg"))              # CEF msg= : "Connection allowed"
        or clean(cef.get("name"))          # CEF header name: "traffic allow"
        or clean(parsed.get("message"))    # plain syslog: "sshd[1234]: Failed password for root"
        or parsed.get("raw")
    )
    return final_dict

def get_username(event_data: dict) -> str | None:
    return clean(event_data.get("TargetUserName")) or clean(event_data.get("SubjectUserName"))

def outcome_from_keywords(keywords) -> str:
    if isinstance(keywords, str):
        keywords = [keywords]
    joined = " ".join(keywords or []).lower()
    if "audit success" in joined:
        return "success"
    if "audit failure" in joined:
        return "failure"
    return "unknown"


def parse_json(line: str) -> dict:
    final_dict = {}
    loaded_json = json.loads(line)
    try:
        event_id = int(loaded_json.get("System", {}).get("EventID"))
    except (TypeError, ValueError):
        event_id = None
    event_meta = EVENT_BY_ID.get(event_id, DEFAULT)
    final_dict["@timestamp"] = iso8601(loaded_json.get("System", {}).get("TimeCreated", None))
    final_dict["event.type"] = event_meta.type.value
    final_dict["event.category"] = event_meta.category.value
    final_dict["event.outcome"] = outcome_from_keywords(loaded_json.get("RenderingInfo", {}).get("Keywords", []))
    final_dict["source.ip"] = clean(loaded_json.get("EventData", {}).get("IpAddress")) or clean(loaded_json.get("OpenWEC", {}).get("IpAddress"))
    final_dict["user.name"] = get_username(loaded_json.get("EventData", {}))
    final_dict["host.name"] = clean(loaded_json.get("System", {}).get("Computer"))
    final_dict["log.level"] = level_from_windows(loaded_json.get("RenderingInfo", {}).get("Level")).value
    final_dict["message"] = clean(loaded_json.get("RenderingInfo", {}).get("Message")) or (f"Windows event {event_id}" if event_id is not None else None) or line
    return final_dict

def error_record(line: str, fmt: str, exc: Exception) -> dict:
    """A schema-valid record for input we couldn't parse, so nothing is silently dropped."""
    return {
        "@timestamp": format_utc(datetime.now(timezone.utc)),
        "event.type": EventType.INFO.value,
        "event.category": Category.HOST.value,
        "event.outcome": Outcome.UNKNOWN.value,
        "message": line,
        "error": f"{fmt} parse failed: {exc}",
    }

def normalize(line: str) -> dict:
    fmt = detect(line)
    try:
        parsed = parse_syslog(line) if fmt == "syslog" else parse_json(line)
        return parsed
    except Exception as exc:
        return error_record(line, fmt, exc)


def clean(value):
    """Normalize Windows Event Log 'absent' sentinels to None."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "" or stripped == "-":
            return None
        return stripped
    return value
