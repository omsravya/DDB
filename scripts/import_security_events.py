"""Command-line entry point for the security-events CSV importer.

The importing logic lives in ``security_events_import.py`` (shared with the
``/import-data`` upload page in the web app). This wrapper just loads the app
environment and calls it.

Usage:
    python scripts/import_security_events.py "/path/to/security_events.csv" [--force]

``--force`` first deletes previously imported rows and reloads; without it the
import is skipped when the incident table already has more than 100 rows.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402  (needs the path tweak above)
from security_events_import import ImportError_, import_csv  # noqa: E402


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    force = "--force" in sys.argv
    if not args:
        print(__doc__)
        return 1

    with app.app.app_context():
        try:
            summary = import_csv(args[0], force=force)
        except ImportError_ as exc:
            print(f"error: {exc}")
            return 1

    if summary.get("skipped"):
        print(f"skipped: incident table already has {summary['existing']} rows; pass --force to reimport.")
        return 0

    counts = summary["counts"]
    print(f"read {summary['rows']} rows")
    for label in ("companies", "incidents", "announcements", "facts", "reviews"):
        print(f"  {label}: +{counts[label]}")
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
