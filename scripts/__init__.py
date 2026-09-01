"""Operational CLIs and demo orchestration — never imported by firewall/
itself (INV-02: nothing here is on any agent-reachable execution path).

Made an explicit package (Phase 6) so `scripts/run_all_demos.py` can
import `scripts.run_bypass_suite`'s public `run_bypass_suite()` function
cleanly, without mypy's "found twice under different module names"
ambiguity between a script run standalone and the same file imported
as a package member.
"""
