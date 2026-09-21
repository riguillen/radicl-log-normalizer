# Log Normalizer Service

A TCP service that accepts RFC 3164 syslog (including CEF) and NDJSON Windows Event Log records, and emits one normalized NDJSON record per input line using the schema in [SCHEMA.md](SCHEMA.md).

**Requirements:** Python 3.11+ (developed on 3.14). No runtime dependencies; pytest for the tests.

```
lognorm/normalize.py   # format detection, parsing, schema mapping: normalize(line) -> dict
lognorm/server.py      # asyncio TCP listener that calls normalize() on each line
tests/test_samples.py
```

## Running

```bash
python3 -m venv .venv && source .venv/bin/activate

python -m lognorm.server                        # 127.0.0.1:5044, NDJSON to stdout
python -m lognorm.server --port 6000            # custom port
python -m lognorm.server --host 0.0.0.0         # accept connections from other machines
python -m lognorm.server --output out.ndjson    # append records to a file instead
```

Records go to stdout (or `--output`). Connection logs and errors go to stderr, so stdout stays valid NDJSON.

In a second terminal:

```bash
cat samples/syslog/*.log | nc -w 1 localhost 5044
jq -c . samples/json/sample-1.json | nc -w 1 localhost 5044      # JSON must be one object per line
printf '{not json\n<134>truncated\n' | nc -w 1 localhost 5044    # malformed input -> error records
```

## Testing

```bash
pip install pytest
python -m pytest -v
```

The tests call `normalize()` directly on the sample files; no server is needed. JSON samples 1 and 2 are compared against `expected/sample-output.ndjson`.

## Format detection: per line

Each line is classified on its own: if the first non-whitespace character is `{`, it's parsed as JSON; otherwise it's parsed as syslog.

I chose per-line over per-connection because one TCP connection from a forwarder can carry logs from several sources in different formats. The check costs a single character comparison, and a malformed line only affects itself, not everything else on the connection.

## Assumptions and trade-offs

- **Syslog timestamps** have no year or timezone. The current year is assumed, moving back a year if the result would be more than a day in the future, and the timezone is assumed to be UTC. JSON timestamps with no timezone are also treated as UTC. All output is ISO 8601 UTC with milliseconds.
- **`event.type` for syslog follows the spec's rule order,** so CEF `act=` is checked before authentication keywords. As a result, a logon arriving as CEF with `act=allow` maps to `allowed`, while the same Windows event 4624 arriving as JSON maps to `start`.
- **`log.level` uses syslog PRI severity (`PRI % 8`), not CEF severity.** The spec's example mapping (6 → info, 4 → warning, 3 → error) matches the syslog scale, and the CEF 0–10 scale runs the other way (higher means more severe). Severity 5 is kept as `notice`.
- **Keyword matching goes beyond the spec's word lists where the samples need it:** "logged on" and "log on" count as authentication, "denied" as failure, and failure words are checked before success words because "unsuccessful" contains "success".
- **`source.ip` for JSON** uses `EventData.IpAddress` and falls back to `OpenWEC.IpAddress`, as the spec says. The OpenWEC value is the collector's address, not the event's origin.
- **Missing values:** `-`, empty strings and whitespace-only strings in optional fields become `null`. Fields are output as `null` rather than left out, so every record has the same keys. The spec's `S-1-0-0` rule doesn't apply here, because the schema has no SID field.
- **Malformed input never crashes the service.** A line that can't be parsed becomes an error record: category `host`, outcome `unknown`, the original line as `message`, and an `error` field saying what failed.
- **TCP:** one coroutine per connection. Lines longer than 1 MiB are dropped with a warning, so a sender that never sends a newline can't make the server buffer indefinitely.

## With more time

- Cap the number of concurrent connections, and close idle ones.
- Write records through a queue with batched writes and a real sink, instead of flushing to stdout one record at a time. At the moment a slow consumer stalls every connection.
- Support RFC 5424 syslog, octet-counted TCP framing (RFC 6587), and CEF escape sequences (`\|`, `\=`).
- Make syslog timezone and severity source configurable per sender, and move the EventID mappings into configuration.
- Keep the original line in an `event.original` field, and add metrics for records processed, error records and dropped lines.