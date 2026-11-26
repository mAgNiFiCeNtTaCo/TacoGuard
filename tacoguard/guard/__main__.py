"""python -m tacoguard.guard --data DIR [--parent PID]: the guard process (see service.py)."""
import sys

from .service import main

if __name__ == "__main__":
    sys.exit(main())
