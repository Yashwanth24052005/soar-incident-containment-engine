"""
Pytest configuration for the SentinelX SOAR test suite.
Ensures the project root is on sys.path so `from app import ...` works
regardless of where pytest is invoked from.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
