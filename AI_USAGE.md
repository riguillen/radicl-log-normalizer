# AI Usage

## Tool

**Claude (Anthropic)**, used through the Claude desktop app as a single long conversation for the whole exercise. I didn't use any other AI tools.

## How I worked with it

I used Claude in three different ways depending on the part of the project:

- **Parsing and schema mapping (`normalize.py`): pair programming.** We worked through it one schema field at a time. For each rule I asked how to approach it, Claude proposed an implementation, and I questioned it, changed the design where I disagreed, integrated it into my code, ran it against the samples, and brought back the output or errors. Claude drafted most of the individual functions; the structure, the design decisions, and the integration were mine.
- **TCP server (`server.py`): written by Claude.** I hadn't built a TCP server before, so Claude wrote it, explained how it works, and tested it. I ran it locally and tested it with the samples and malformed input.
- **Documentation (`README.md`, `AI_USAGE.md`): drafted by Claude** from our conversation. I reviewed and edited both.

## Parsing and mapping (`normalize.py`)

**What I wrote or shaped**
- **Wrote the first version of the Windows JSON mapping (`parse_json`) and `get_username` myself.** I then fixed the bugs Claude pointed out: the wrong field name (`ComputerName` instead of `Computer`), an output key missing its `event.` prefix, a keyword check on a list that never matched, and later the order of cleaning inside `get_username`.
- **Put together `format_syslog`, `syslog_event_type`, `syslog_event_category`, `syslog_outcome`, `outcome_from_keywords`** and integrated each piece into the pipeline as it came in.
- **Added enums and lookup tables instead of chains of `if` statements** for event type, category and log level. That shaped how all the mapping code is organized.
- **Designed the EventID table as a flat ID → (type, category) mapping.** 
- **Questioned rules until they either held up or changed.** I asked whether the 4720–4767 range rule did anything (it didn't, so it was dropped). I asked why PRI and CEF severity differ on the same line (that led to choosing PRI deliberately). And I asked why `act=` overrides an authentication message (that surfaced the `event.type` ordering decision).
- **Made the design calls documented in the README:** spec order for `event.type`, PRI severity for `log.level`, keeping `notice` for severity 5, the OpenWEC fallback for `source.ip`, and `null` rather than omitting optional fields. Claude laid out the options and trade-offs; I chose.

**What Claude drafted**
- The syslog parsing: `SYSLOG_RE`, the CEF header split, and `parse_cef_extensions`.
- The timestamp helpers: `iso8601`, `format_utc`, and `syslog_timestamp`.
- `clean()`, `error_record`, and the `message` fallback chains.
- Before I started, Claude also pointed out the traps in the sample data: CEF values containing spaces, syslog timestamps with no year, 7-digit fractional seconds, `-` sentinel values, and the flat dotted output keys.

## Mistakes in the AI output, and how they were caught

- **A helper that treated `S-1-5-7` as a null SID.** That SID is actually Anonymous Logon, a real identity. Claude flagged this itself, and the helper was removed, since the schema has no SID field.
- **The first draft of the TCP server** passed the tail of a line over the 1 MiB limit through as a new line. Claude found this while testing and replaced the approach.
- **An early skeleton used `...` as a function body,** which made `normalize()` return `None`. I hit the error, and we fixed it.
- **The spec's category keyword list** (`logon`, `login`, `auth`) doesn't match the samples' wording ("logged on", "log on"). This was found by testing against the samples.

## How the code was checked

- Every piece was run against all six samples before it was kept. JSON samples 1 and 2 match `expected/sample-output.ndjson` field for field.
- Edge cases were tested directly: sentinel values, missing fields, `EventID` sent as a string, invalid JSON, truncated syslog, oversized lines, and several connections at once.
- Re-running after changes caught a regression I introduced myself: sample 3's `user.name` stopped coming through (`DC01$` became `null`) after I changed the cleaning order in `get_username`.

I've read all of the code in this repo, and I can explain each part of it and the reasons behind each design choice.