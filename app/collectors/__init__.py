"""Agentless collectors (Phase 4): scheduled pull of vendor logs into ingest."""
from .base import Collector, FetchResult
from .runner import (CollectorScheduler, build_collectors, get_scheduler,
                     run_collector, set_scheduler)

__all__ = ["Collector", "FetchResult", "CollectorScheduler", "build_collectors",
           "get_scheduler", "run_collector", "set_scheduler"]
