import json
import pathlib

import pytest

from lognorm.normalize import normalize

ROOT = pathlib.Path(__file__).parent.parent
JSON_EXPECTED = [
    json.loads(line)
    for line in (ROOT / "expected" / "sample-output.ndjson").read_text().splitlines()
    if line.strip()
]

SYSLOG_EXPECTED = ["""{"@timestamp": "2025-12-05T10:30:45.000Z", "event.type": "allowed", "event.category": "authentication", "event.outcome": "success", "source.ip": "10.0.50.42", "user.name": "jsmith", "host.name": "192.168.1.1", "log.level": "info", "message": "An account was successfully logged on"}""",
"""{"@timestamp": "2025-12-05T10:35:22.000Z", "event.type": "denied", "event.category": "authentication", "event.outcome": "failure", "source.ip": "10.99.0.55", "user.name": "admin", "host.name": "192.168.1.1", "log.level": "notice", "message": "An account failed to log on"}"""]


def load_json_sample(name: str) -> str:
    return json.dumps(json.loads((ROOT / "samples" / "json" / name).read_text()))

def load_syslog_sample(name: str) -> str:
    return (ROOT / "samples" / "syslog" / name).read_text().strip()


@pytest.mark.parametrize("sample, expected", [
    ("sample-1.json", JSON_EXPECTED[0]),
    ("sample-2.json", JSON_EXPECTED[1]),
])
def test_json_sample_matches_expected_output(sample, expected):
    assert normalize(load_json_sample(sample)) == expected

@pytest.mark.parametrize("sample, expected", [
    ("sample-1.log", SYSLOG_EXPECTED[0]),
    ("sample-2.log", SYSLOG_EXPECTED[1]),
])
def test_syslog_sample_matches_expected_output(sample, expected):
    assert normalize(load_syslog_sample(sample)) == json.loads(expected)