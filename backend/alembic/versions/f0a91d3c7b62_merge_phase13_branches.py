"""Merge the two phase-13 branches.

Two migrations were authored against the same parent (b8e5a2f71c93) in
parallel: c4d7b2a95e18, the truth pass, and 7cd8df59f1d1, notifications and
ticketing. Neither is wrong and they touch different tables — the truth pass
adds integration_state and columns on attack_paths, attack_surface_domains and
scan_schedules, while the other adds the notifications and ticket_integrations
tables. What they created between them is a fork, and `alembic upgrade head`
refuses a fork: it cannot know which of two heads "head" means, so it applies
neither and the database silently stays where it was.

This is an empty merge point. It creates and drops nothing; it exists so the
graph has a single head again and both branches are reachable from it.

Revision ID: f0a91d3c7b62
Revises: d5e8c3b06f27, 7cd8df59f1d1
Create Date: 2026-08-23
"""
from __future__ import annotations

revision = "f0a91d3c7b62"
down_revision = ("d5e8c3b06f27", "7cd8df59f1d1")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Nothing to do: both parents have already made their changes."""


def downgrade() -> None:
    """Nothing to undo; reversing past this point splits the graph again."""
