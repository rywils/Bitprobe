# NexProbe Security Assessment Report

**Client:** ryanwilsonio  
**Target:** https://ryanwilson.io  
**Date:** December 10, 2025  
**Scan ID:** scan_20251210_004553  

---
## Executive Summary

This report presents the findings of an automated security assessment performed using **NexProbe**. The objective of this assessment was to identify security weaknesses, misconfigurations, and known vulnerabilities that could impact the confidentiality, integrity, or availability of the target system.

### Overall Risk Posture

- **Overall Risk Level:** `MEDIUM`  
- **Risk Score:** 22.5 / 100 (raw: 23.65)  

### Risk Overview by Severity

- **MEDIUM**: 4
- **LOW**: 2
- **INFO**: 1

**Total Findings:** 7  
**URLs Scanned:** 1  
**Scan Duration:** 14.7 seconds  

---
## Detailed Findings

### 1. Technology Fingerprinting
**Severity:** `INFO`  
**Risk Score (per finding):** 0.25  
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

### 2. Open Network Port Detected: 80 (HTTP)
**Severity:** `MEDIUM`  
**Risk Score (per finding):** 5.2  
**Affected URL:** ryanwilson.io:80  

**Description:**
The service HTTP is exposed on TCP port 80.

**Evidence:**
```json
{'port': 80, 'service': 'HTTP', 'banner': 'HTTP/1.1 400 Bad Request\r\nDate: Wed, 10 Dec 2025 06:46:01 GMT\r\nContent-Length: 68\r\nConnection: close\r\nCache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nReferrer-Policy: same-origin\r\nExpires: Thu, 01 Jan 1970 00:00:01 GMT\r\nProxy-Status: Cloudflare-Proxy;error=http_request_error\r\nCF-RAY: 9abac86609d4fa17-ORD'}
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

### 3. Open Network Port Detected: 443 (HTTPS)
**Severity:** `MEDIUM`  
**Risk Score (per finding):** 5.2  
**Affected URL:** ryanwilson.io:443  

**Description:**
The service HTTPS is exposed on TCP port 443.

**Evidence:**
```json
{'port': 443, 'service': 'HTTPS', 'banner': 'HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nDate: Wed, 10 Dec 2025 06:46:04 GMT\r\nContent-Type: text/html\r\nContent-Length: 253\r\nConnection: close\r\nCF-RAY: -'}
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

### 4. Open Network Port Detected: 8080 (HTTP-Alt)
**Severity:** `MEDIUM`  
**Risk Score (per finding):** 5.2  
**Affected URL:** ryanwilson.io:8080  

**Description:**
The service HTTP-Alt is exposed on TCP port 8080.

**Evidence:**
```json
{'port': 8080, 'service': 'HTTP-Alt', 'banner': 'HTTP/1.1 400 Bad Request\r\nDate: Wed, 10 Dec 2025 06:46:08 GMT\r\nContent-Length: 68\r\nConnection: close\r\nCache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nReferrer-Policy: same-origin\r\nExpires: Thu, 01 Jan 1970 00:00:01 GMT\r\nProxy-Status: Cloudflare-Proxy;error=http_request_error\r\nCF-RAY: 9abac88d0ed18722-ORD'}
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

### 5. Open Network Port Detected: 8443 (HTTPS-Alt)
**Severity:** `MEDIUM`  
**Risk Score (per finding):** 5.2  
**Affected URL:** ryanwilson.io:8443  

**Description:**
The service HTTPS-Alt is exposed on TCP port 8443.

**Evidence:**
```json
{'port': 8443, 'service': 'HTTPS-Alt', 'banner': 'HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nDate: Wed, 10 Dec 2025 06:46:08 GMT\r\nContent-Type: text/html\r\nContent-Length: 253\r\nConnection: close\r\nCF-RAY: -'}
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

### 6. TLS Configuration on Port 443
**Severity:** `LOW`  
**Risk Score (per finding):** 1.3  
**Affected URL:** ryanwilson.io:443  

**Description:**
TLS is enabled on port 443 using protocol TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256-bit).

**Evidence:**
```json
{'port': 443, 'protocol': 'TLSv1.3', 'cipher': ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256), 'not_after': 'Feb 25 12:11:31 2026 GMT', 'days_until_expiry': 77, 'subject': 'commonName=ryanwilson.io', 'issuer': 'countryName=US, organizationName=Google Trust Services, commonName=WE1'}
```

### How an attacker may exploit this vulnerability
If TLS is misconfigured (expired certificate, weak protocols, or poor ciphers), attackers may intercept or manipulate traffic, downgrade encryption, or perform man-in-the-middle attacks.

### How defense would mitigate this attack vector
Use strong TLS configurations with modern protocols (TLS 1.2+), valid certificates, and trusted certificate authorities. Enforce HSTS where applicable.

### Plan for risk management and mitigation
The IT team should ensure all public services use modern TLS versions, renew certificates before expiration, disable weak protocols, and verify configurations through continuous monitoring.

**Remediation:**
Renew certificates before expiration and ensure only modern TLS protocols and strong ciphers are enabled.

---

### 7. TLS Configuration on Port 8443
**Severity:** `LOW`  
**Risk Score (per finding):** 1.3  
**Affected URL:** ryanwilson.io:8443  

**Description:**
TLS is enabled on port 8443 using protocol TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256-bit).

**Evidence:**
```json
{'port': 8443, 'protocol': 'TLSv1.3', 'cipher': ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256), 'not_after': 'Feb 25 12:11:31 2026 GMT', 'days_until_expiry': 77, 'subject': 'commonName=ryanwilson.io', 'issuer': 'countryName=US, organizationName=Google Trust Services, commonName=WE1'}
```

### How an attacker may exploit this vulnerability
If TLS is misconfigured (expired certificate, weak protocols, or poor ciphers), attackers may intercept or manipulate traffic, downgrade encryption, or perform man-in-the-middle attacks.

### How defense would mitigate this attack vector
Use strong TLS configurations with modern protocols (TLS 1.2+), valid certificates, and trusted certificate authorities. Enforce HSTS where applicable.

### Plan for risk management and mitigation
The IT team should ensure all public services use modern TLS versions, renew certificates before expiration, disable weak protocols, and verify configurations through continuous monitoring.

**Remediation:**
Renew certificates before expiration and ensure only modern TLS protocols and strong ciphers are enabled.

---

