# Panopticon Phase 6 Brief

Implement Phase 6 for Panopticon: alert visibility and telemetry.

Deliverables:
1. Persist alerts to session.alerts.jsonl in panopticon/export/
2. Add/reveal an Alerts panel in panopticon/ui/
3. Print alert summary counts at shutdown in analyzer.py
4. Add tests in panopticon/tests/
5. Update README.md Phase 6 status line

Constraints:
- do not change detector semantics
- follow existing export/ui/test patterns
- keep tests offline
- pytest -q must stay green
