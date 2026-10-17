# TODO: Fix errors in capture/capture_manager.py

## Steps
- [x] Analyze logs/app.log to identify root causes
- [x] Fix unused import (DNSQR)
- [x] Add `_normalize_interface()` helper (Windows Npcap `\Device\NPF_` prefix)
- [x] Rewrite `_get_default_interface()` to prioritize Config + auto-detect
- [x] Normalize interface in `__init__`
- [x] Validate interface before starting sniff thread
- [x] Honor `count`/`timeout` parameters in `sniff_loop`
- [x] Verify module imports / run capture test

