# Cover6 First Watch – Day 5: Internal Reconnaissance

**Incident:** Odapeeka State University  
**Analyst:** Sami Qasem  
**Date:** 21–22 November 2026  
**Source:** Splunk · `index=main` · `host=odapeeka` · `sourcetype=access_combined`  
**Time Range:** Last 24 hours

---

## Executive Summary

Investigation focused on indicators of Internal Reconnaissance, specifically attempts to access sensitive local files and references to internal network addresses.

- Three attempts to access sensitive local files were observed.
- No requests containing internal IP addresses or localhost references were found.
- All observed file access attempts returned non-successful status codes (404, 301, 400).

---

## 1. Sensitive Local File Access Attempts

```spl
index=main host=odapeeka sourcetype=access_combined 
(uri="*/etc/passwd*" OR uri="*shadow*" OR uri="*../.."* OR uri="*boot.ini*") 
AND (NOT uri="*splunk*") 
| table _time, clientip, uri, status
```

![Sensitive File Access](evidence/01-sensitive-files.png)

**Result:** 3 events

| Time                | Client IP      | URI              | Status |
|---------------------|----------------|------------------|--------|
| 2026-11-21 23:28:09 | 116.179.32.92  | `/etc/passwd`    | 404    |
| 2026-11-21 23:28:08 | 116.179.32.150 | `/etc/passwd`    | 301    |
| 2026-11-21 23:03:56 | 185.177.72.64  | `../../.env`     | 400    |

Attempts targeted common sensitive files (`/etc/passwd` and `.env` via path traversal). None returned a successful 200 response.

---

## 2. Internal Network / Localhost References

```spl
index=main host=odapeeka sourcetype=access_combined 
(uri="*127.0.0.1*" OR uri="*localhost*" OR uri="*192.168*" OR uri="*10.0*") 
AND (NOT uri="*splunk*") 
| table _time, clientip, uri, status
```

![Internal IP References](evidence/02-internal-ips.png)

**Result:** 0 events

No requests containing references to localhost or private IP ranges were observed in the web access logs.

---

## Key Findings

- Limited attempts to access sensitive local files (`/etc/passwd` and `.env`) were detected.
- All attempts failed (status codes 404, 301, and 400).
- No evidence of internal network reconnaissance via web requests (no localhost or private IP references).
- At this stage, there is no strong indication of successful internal reconnaissance activity from the available web logs.

---

## Evidence

| File | Description |
|------|-------------|
| `evidence/01-sensitive-files.png` | Attempts to access `/etc/passwd` and `.env` |
| `evidence/02-internal-ips.png` | Search for internal IP / localhost references (0 results) |

---

**End of Day 5 Report**
