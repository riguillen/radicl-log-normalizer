"""TCP listener: reads newline-delimited logs, writes normalized NDJSON."""
import argparse
import asyncio
import json
import logging
import sys

from lognorm.normalize import normalize

log = logging.getLogger("lognorm.server")

MAX_LINE_BYTES = 1 << 20  # 1 MiB; longer lines are dropped instead of buffered forever


async def read_lines(reader, peer):
    """Yield one newline-delimited line at a time from a TCP stream."""
    while True:
        try:
            yield await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            if exc.partial:  # client closed without a trailing newline
                yield exc.partial
            return
        except asyncio.LimitOverrunError:
            log.warning("%s: line longer than %d bytes, dropped", peer, MAX_LINE_BYTES)
            if not await discard_rest_of_line(reader):
                return


async def discard_rest_of_line(reader):
    """Throw away an oversized line up to its newline. False if the client disconnected."""
    while True:
        try:
            await reader.readuntil(b"\n")
            return True
        except asyncio.LimitOverrunError as exc:
            await reader.readexactly(exc.consumed)
        except asyncio.IncompleteReadError:
            return False


async def handle_connection(reader, writer, sink):
    peer = writer.get_extra_info("peername")
    log.info("connection from %s", peer)
    try:
        async for raw in read_lines(reader, peer):
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                record = normalize(line)
            except Exception:
                log.exception("%s: could not normalize line: %.200s", peer, line)
                continue
            sink.write(json.dumps(record) + "\n")
            sink.flush()
    except ConnectionResetError:
        log.info("%s reset the connection", peer)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        log.info("closed %s", peer)


async def serve(host, port, sink):
    server = await asyncio.start_server(
        lambda r, w: handle_connection(r, w, sink), host, port, limit=MAX_LINE_BYTES
    )
    for sock in server.sockets:
        log.info("listening on %s", sock.getsockname())
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Log normalizer TCP service")
    parser.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to accept remote senders")
    parser.add_argument("--port", type=int, default=5044)
    parser.add_argument("--output", help="append NDJSON to this file instead of stdout")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")

    sink = open(args.output, "a", encoding="utf-8") if args.output else sys.stdout
    try:
        asyncio.run(serve(args.host, args.port, sink))
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        if sink is not sys.stdout:
            sink.close()


if __name__ == "__main__":
    main()