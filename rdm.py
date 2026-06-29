#!/usr/bin/env python3
"""Thin launcher so `python3 rdm.py` works from the repo root."""
from rdm.__main__ import main

raise SystemExit(main())
