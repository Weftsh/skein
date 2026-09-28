#!/usr/bin/env python3
"""Re-record the npmjs documents the fixture test holds the fake to.

    python3 scripts/record-npm-fixtures.py

Fetches each package's packument from registry.npmjs.org and keeps only
the parts the product reads — `name`, `dist-tags`, and for five versions
their `name`, `version`, `license`, `licenses`, `dist` and `dependencies`,
plus the sibling `time` map — so a diff of a re-recording shows what
npmjs changed rather than a megabyte of README. Commit what it writes; if
a field moved, `upstream_fixtures_parse_like_the_fake` goes red.
"""

import json
import os
import urllib.request

PACKAGES = {
    # The oldest releases declare "BSD", which is three licences: the
    # ambiguous case, from the wild rather than invented.
    "left-pad": ["0.0.0", "0.0.1", "0.0.3", "0.0.9", "1.0.1"],
    "is-number": None,
    "lodash": None,
}
KEEP = ("name", "version", "license", "licenses", "dist", "dependencies")
OUT = os.path.join(os.path.dirname(__file__), "..", "crates", "skein-testkit", "fixtures", "registry")


def record(name, pick):
    with urllib.request.urlopen(f"https://registry.npmjs.org/{name}", timeout=60) as r:
        doc = json.load(r)
    versions = pick or list(doc["versions"])[-5:]
    out = {
        "name": doc["name"],
        "dist-tags": {k: v for k, v in doc["dist-tags"].items() if v in versions},
        "versions": {
            v: {k: doc["versions"][v][k] for k in KEEP if k in doc["versions"][v]}
            for v in versions
        },
        "time": {v: doc["time"][v] for v in versions if v in doc.get("time", {})},
    }
    path = os.path.join(OUT, f"npm-{name}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"recorded {name}: {', '.join(versions)} -> {os.path.normpath(path)}")


if __name__ == "__main__":
    for name, pick in PACKAGES.items():
        record(name, pick)
