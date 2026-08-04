# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Live log receivers.

Currently: syslog (UDP/TCP/TLS, Phase 1) and NetFlow v5/v9/IPFIX (UDP, plus optional
IPFIX-over-TCP, Phase 2). Both submit parsed events to the shared
`app.streaming.IngestQueue` rather than writing to Postgres on the hot path, and both
are constructed and started from the app lifespan — host and ports are constructor
arguments, never `settings` reads, so a receiver is testable with no global config.
"""
