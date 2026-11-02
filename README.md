# Threat Intelligence Platform

SSH honeypot (Cowrie) feeding a FastAPI backend that stores, enriches and scores attack sessions, with a React dashboard.

```
Cowrie  ->  Vector  ->  FastAPI /ingest  ->  PostgreSQL (JSONB)
                              |
                              +-> Celery/Redis: GeoLite2, AbuseIPDB, VirusTotal enrichment
                              +-> IOC extraction, threat scoring, behaviour -> MITRE ATT&CK
                              +-> REST API (~20 endpoints)  ->  React dashboard
```

## Features
- Log shipping from Cowrie JSON logs with Vector into the `/ingest` endpoint.
- Asynchronous enrichment: GeoLite2 city/ASN, AbuseIPDB reputation, VirusTotal lookups.
- IOC extraction (URLs, IPs, hashes, file paths) from attacker commands.
- Rule-based threat scoring (LOW / MEDIUM / HIGH) and behaviour patterns mapped to MITRE ATT&CK techniques and kill-chain stages.
- Dashboard: attack map, top IPs / ASNs / countries, commands, high-risk sessions, per-session timeline.

## Run (lab setup)
1. Start the stack: `docker compose up -d` (PostgreSQL, Redis, Vector) and the honeypot in `honeypots/cowrie`.
2. Download the MaxMind GeoLite2 City and ASN databases into `backend/data/geoip/` and the MITRE ATT&CK enterprise JSON into `backend/data/attack/enterprise-attack.json`.
3. Set `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` in your environment.
4. Backend: `cd backend && pip install -r requirements.txt && uvicorn app.main:app --port 8000`, plus a Celery worker.
5. Frontend: `cd frontend && npm install && npm run dev`.

## Notes
- The credentials in `docker-compose.yaml` are lab defaults. Change them for anything exposed to a network.
- Scoring is rule-based; no machine learning is used for detection.
- Only the Cowrie honeypot is wired up.
