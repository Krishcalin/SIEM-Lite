"""Notifications (Phase 3): fan newly-raised alerts out to channels."""
from .dispatcher import (NotificationDispatcher, build_dispatcher, get_dispatcher,
                         set_dispatcher, submit_alerts)

__all__ = ["NotificationDispatcher", "build_dispatcher", "get_dispatcher",
           "set_dispatcher", "submit_alerts"]
