"""
CyberShield AI — PISF Agent Test Suite Runner Alias
====================================================
Alias for test_pisf_reachability.py to ensure both module names execute
the full 37-test PISF 2026 reachability and control suite.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_pisf_reachability import *  # noqa: F401, F403

if __name__ == "__main__":
    import pytest
    pytest.main([os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_pisf_reachability.py")])
