"""Allow running the scanner as ``python -m iacscanner``."""
from iacscanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
