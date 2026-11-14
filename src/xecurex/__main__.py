"""Allow running xecurex as a module: python -m xecurex"""

import sys

from xecurex.cli import main

if __name__ == "__main__":
    sys.exit(main())
