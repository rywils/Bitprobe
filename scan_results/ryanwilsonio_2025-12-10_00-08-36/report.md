# NexProbe Security Assessment Report
**Client:** ryanwilsonio  
**Target:** https://ryanwilson.io  
**Date:** December 10, 2025  
**Scan ID:** scan_20251210_000836  

---
## Executive Summary
This report presents the findings of an automated security assessment performed using **NexProbe**. The objective of this assessment was to identify security weaknesses, misconfigurations, and known vulnerabilities that could impact the confidentiality, integrity, or availability of the target system.

### Risk Overview
- **HIGH**: 1
- **MEDIUM**: 5
- **INFO**: 1

**Total Findings:** 7  
**URLs Scanned:** 1  
**Scan Duration:** 14.41 seconds  

---
## Detailed Findings

### 1. Technology Fingerprinting
**Severity:** `INFO`  
**Affected URL:** https://ryanwilson.io  

**Description:**
Passive identification of technologies used by the target

**Evidence:**
```json
{'server': 'cloudflare', 'cdn': 'cloudflare', 'waf': 'cloudflare'}
```

### How an attacker may exploit this vulnerability


### How defense would mitigate this attack vector


### Plan for risk management and mitigation


**Remediation:**
Use this information to correlate against known CVEs and version-specific vulnerabilities.

---

### 2. Exposed Sensitive File: .htaccess
**Severity:** `MEDIUM`  
**Affected URL:** https://ryanwilson.io/.htaccess  

**Description:**
The file '.htaccess' is publicly accessible and appears to contain sensitive information.

**Evidence:**
```json
{'path': '.htaccess', 'status_code': 200, 'content_length': 9883, 'content_type': 'text/html'}
```

### How an attacker may exploit this vulnerability
If an attacker gains access to the exposed file '.htaccess', they may extract sensitive information such as credentials, internal configuration details, source code, or backup data. This information could be used to escalate privileges or pivot further into internal systems.

### How defense would mitigate this attack vector
Sensitive files should never be directly exposed to the public internet. Defense involves restricting file access at the web server or CDN layer and ensuring that sensitive artifacts are stored outside of the web root.

### Plan for risk management and mitigation
The IT team should immediately remove publicly exposed sensitive files, audit deployment pipelines for accidental leakage, validate web root contents, and implement automated checks in CI/CD to prevent re-exposure in future builds.

**Remediation:**
Remove or restrict access to '.htaccess' using proper access controls.

---

### 3. Exposed Sensitive File: dump.sql
**Severity:** `HIGH`  
**Affected URL:** https://ryanwilson.io/dump.sql  

**Description:**
The file 'dump.sql' is publicly accessible and appears to contain sensitive information.

**Evidence:**
```json
{'path': 'dump.sql', 'status_code': 200, 'content_length': 9883, 'content_type': 'text/html'}
```

### How an attacker may exploit this vulnerability
If an attacker gains access to the exposed file 'dump.sql', they may extract sensitive information such as credentials, internal configuration details, source code, or backup data. This information could be used to escalate privileges or pivot further into internal systems.

### How defense would mitigate this attack vector
Sensitive files should never be directly exposed to the public internet. Defense involves restricting file access at the web server or CDN layer and ensuring that sensitive artifacts are stored outside of the web root.

### Plan for risk management and mitigation
The IT team should immediately remove publicly exposed sensitive files, audit deployment pipelines for accidental leakage, validate web root contents, and implement automated checks in CI/CD to prevent re-exposure in future builds.

**Remediation:**
Remove or restrict access to 'dump.sql' using proper access controls.

---

### 4. Open Network Port Detected: 80 (HTTP)
**Severity:** `MEDIUM`  
**Affected URL:** ryanwilson.io:80  

**Description:**
The service HTTP is exposed on TCP port 80.

**Evidence:**
```json
{'port': 80, 'service': 'HTTP', 'banner': 'HTTP/1.1 400 Bad Request\r\nDate: Wed, 10 Dec 2025 06:08:44 GMT\r\nContent-Length: 68\r\nConnection: close\r\nCache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nReferrer-Policy: same-origin\r\nExpires: Thu, 01 Jan 1970 00:00:01 GMT\r\nProxy-Status: Cloudflare-Proxy;error=http_request_error\r\nCF-RAY: 9aba91c4af7a615f-ORD'}
```

### How an attacker may exploit this vulnerability
An attacker could directly interact with the exposed HTTP service on port 80. If authentication is weak or misconfigured, this could allow unauthorized system access, data extraction, or full infrastructure compromise.

### How defense would mitigate this attack vector
Exposed services should be restricted using network firewalls, access control lists (ACLs), and zero-trust segmentation. Only systems that explicitly require access should be permitted.

### Plan for risk management and mitigation
The IT team should review firewall rules, confirm that the exposed service is required, enforce strong authentication, disable unused services, and verify remediation via rescanning.

**Remediation:**
If HTTP is not required to be publicly accessible, restrict access via firewall rules. Otherwise, enforce authentication, encryption, and continuous monitoring.

---

### 5. Open Network Port Detected: 443 (HTTPS)
**Severity:** `MEDIUM`  
**Affected URL:** ryanwilson.io:443  

**Description:**
The service HTTPS is exposed on TCP port 443.

**Evidence:**
```json
{'port': 443, 'service': 'HTTPS', 'banner': 'HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nDate: Wed, 10 Dec 2025 06:08:46 GMT\r\nContent-Type: text/html\r\nContent-Length: 253\r\nConnection: close\r\nCF-RAY: -'}
```

### How an attacker may exploit this vulnerability
An attacker could directly interact with the exposed HTTPS service on port 443. If authentication is weak or misconfigured, this could allow unauthorized system access, data extraction, or full infrastructure compromise.

### How defense would mitigate this attack vector
Exposed services should be restricted using network firewalls, access control lists (ACLs), and zero-trust segmentation. Only systems that explicitly require access should be permitted.

### Plan for risk management and mitigation
The IT team should review firewall rules, confirm that the exposed service is required, enforce strong authentication, disable unused services, and verify remediation via rescanning.

**Remediation:**
If HTTPS is not required to be publicly accessible, restrict access via firewall rules. Otherwise, enforce authentication, encryption, and continuous monitoring.

---

### 6. Open Network Port Detected: 8080 (HTTP-Alt)
**Severity:** `MEDIUM`  
**Affected URL:** ryanwilson.io:8080  

**Description:**
The service HTTP-Alt is exposed on TCP port 8080.

**Evidence:**
```json
{'port': 8080, 'service': 'HTTP-Alt', 'banner': 'HTTP/1.1 400 Bad Request\r\nDate: Wed, 10 Dec 2025 06:08:50 GMT\r\nContent-Length: 68\r\nConnection: close\r\nCache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nReferrer-Policy: same-origin\r\nExpires: Thu, 01 Jan 1970 00:00:01 GMT\r\nProxy-Status: Cloudflare-Proxy;error=http_request_error\r\nCF-RAY: 9aba91ebbcb1e227-ORD'}
```

### How an attacker may exploit this vulnerability
An attacker could directly interact with the exposed HTTP-Alt service on port 8080. If authentication is weak or misconfigured, this could allow unauthorized system access, data extraction, or full infrastructure compromise.

### How defense would mitigate this attack vector
Exposed services should be restricted using network firewalls, access control lists (ACLs), and zero-trust segmentation. Only systems that explicitly require access should be permitted.

### Plan for risk management and mitigation
The IT team should review firewall rules, confirm that the exposed service is required, enforce strong authentication, disable unused services, and verify remediation via rescanning.

**Remediation:**
If HTTP-Alt is not required to be publicly accessible, restrict access via firewall rules. Otherwise, enforce authentication, encryption, and continuous monitoring.

---

### 7. Open Network Port Detected: 8443 (HTTPS-Alt)
**Severity:** `MEDIUM`  
**Affected URL:** ryanwilson.io:8443  

**Description:**
The service HTTPS-Alt is exposed on TCP port 8443.

**Evidence:**
```json
{'port': 8443, 'service': 'HTTPS-Alt', 'banner': 'HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nDate: Wed, 10 Dec 2025 06:08:50 GMT\r\nContent-Type: text/html\r\nContent-Length: 253\r\nConnection: close\r\nCF-RAY: -'}
```

### How an attacker may exploit this vulnerability
An attacker could directly interact with the exposed HTTPS-Alt service on port 8443. If authentication is weak or misconfigured, this could allow unauthorized system access, data extraction, or full infrastructure compromise.

### How defense would mitigate this attack vector
Exposed services should be restricted using network firewalls, access control lists (ACLs), and zero-trust segmentation. Only systems that explicitly require access should be permitted.

### Plan for risk management and mitigation
The IT team should review firewall rules, confirm that the exposed service is required, enforce strong authentication, disable unused services, and verify remediation via rescanning.

**Remediation:**
If HTTPS-Alt is not required to be publicly accessible, restrict access via firewall rules. Otherwise, enforce authentication, encryption, and continuous monitoring.

---

