![Alt text](./bitprobe.png "Nexprobe")
# BitProbe


---

**BitProbe** is a modular security reconnaissance and vulnerability assessment framework designed for continuous web, network, and TLS analysis. 

This repository contains the **public demonstration** of BitProbe. The full scanning engine and remainder of the project remains private.

---

## Features

### Public Current State (This Repository)


- Passive technology fingerprinting (server, framework, CDN, analytics, WAF)
- Network port enumeration and basic service identification
- TLS configuration and certificate inspection
- Security header analysis
- Sensitive file and misconfiguration detection
- CVE correlation using a local vulnerability database
- Automated attack-chain correlation
- Client-ready structured output (JSON)
- Transparent risk scoring per finding
- Non-intrusive scanning only
---

### Private / Current State (Not Publicly Released)

- Crawls web targets with depth control and URL limits
- Runs all plugins by default at root, scoped intelligently for subpaths
- Detects and flags edge/CDN infrastructure explicitly
- Preserves edge findings instead of suppressing the
- Calculates raw risk scores before edge filtering
- Calculates adjusted risk scores after edge context
- Differentiates origin vs edge findings (edge_infrastructure=true)
- Correlates findings into basic attack chains
- Uses weighted risk scoring (impact × likelihood, normalized)
- Produces defensible, auditable findings suitable for client delivery
>  These remain proprietary and are **not included** in the public repository.


## Example Usage

```bash
python3 bitprobe.py \
  --target https://example.com \
  --plugins fingerprinting,security_headers,network_scanner,tls_analysis
```

---

## Security Notice

This repository does NOT contain exploit code or active offensive tooling.
It is intended for defensive security testing, portfolio demonstration, and educational research only.

Unauthorized use against systems you do not own or have permission to test is prohibited.

## License

MIT License — Public interface only. Core engine remains proprietary.

Built as an independent security engineering project and portfolio platform.
Client-facing versions are deployed privately with extended modules.


