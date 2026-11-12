# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing

from sqlalchemy.orm import Mapped, mapped_column

from warehouse.constants import RateLimitPeriod

if typing.TYPE_CHECKING:
    from pyramid.request import Request


class HasProjectCreateRateLimit:
    """
    Mixin for models (users, organizations) that can carry a per-entity override
    of the project creation rate limit.

    Models using this must also define a CheckConstraint ensuring that both
    columns are NULL together, and provide ``record_event`` (see ``HasEvents``).
    """

    project_create_ratelimit_count: Mapped[int | None] = mapped_column(
        comment=(
            "Project creation rate limit count, e.g. the 20 in '20 per hour'. "
            "NULL means no override: the configured default applies."
        ),
    )
    project_create_ratelimit_period: Mapped[RateLimitPeriod | None] = mapped_column(
        comment=(
            "Period the count is measured over. Must be NULL exactly when "
            "project_create_ratelimit_count is NULL."
        ),
    )

    @property
    def project_create_ratelimit_string(self) -> str | None:
        """Composed `limits`-syntax string, or None when no override is set."""
        count = self.project_create_ratelimit_count
        period = self.project_create_ratelimit_period
        if count is None and period is None:
            return None
        if count is None or period is None:
            raise ValueError(
                "Project creation rate limit requires both count and period"
            )
        return f"{count} per {period.value}"

    def set_project_create_ratelimit(
        self,
        *,
        count: int | None,
        period: RateLimitPeriod | None,
        tag,
        request: Request,
    ) -> str | None:
        """Apply a new override (or clear it) and record the change as an event."""
        previous = self.project_create_ratelimit_string
        self.project_create_ratelimit_count = count
        self.project_create_ratelimit_period = period if count is not None else None

        self.record_event(  # type: ignore[attr-defined]
            tag=tag,
            request=request,
            additional={
                "old_project_create_ratelimit_string": previous,
                "new_project_create_ratelimit_string": (
                    self.project_create_ratelimit_string
                ),
                "actor": request.user.username,
            },
        )
        return self.project_create_ratelimit_string
