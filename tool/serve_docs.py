#!/usr/bin/env python3
"""Serve the built Jaspr docs on 0.0.0.0:8080.

The site sets <base href="/pqforge/">, so both / and /pqforge/ must resolve
to the same files.
"""

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "site" / "build" / "jaspr"
PREFIX = "/pqforge"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        self._strip_prefix()
        super().do_GET()

    def do_HEAD(self):
        self._strip_prefix()
        super().do_HEAD()

    def _strip_prefix(self):
        path = self.path
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)
            query = "?" + query
        if path == PREFIX or path.startswith(PREFIX + "/"):
            path = path[len(PREFIX) :] or "/"
        self.path = path + query


def main():
    if not (ROOT / "index.html").is_file():
        raise SystemExit(f"missing Jaspr build at {ROOT}")
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
