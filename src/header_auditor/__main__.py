"""Permite ejecutar la herramienta con ``python -m header_auditor``."""

import sys

from .cli import main

sys.exit(main())
