"""Entrypoint for `python -m mailguard` execution."""

import sys
from mailguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
