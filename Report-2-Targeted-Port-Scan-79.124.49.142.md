# 📄 Report 2 — Targeted Port Scanning Attack from Bulgaria

## 1. Incident Overview

| Field | Details |
|---|---|
| **Report Date** | 07 May 2026 |
| **Analyst** | Thumma Lakshmikanth Gari Dinesh |
| **Severity** | 🔴 High |
| **Status** | Investigated |
| **Tools Used** | Splunk Enterprise Security + VirusTotal + Cisco Talos |
| **Classification** | ✅ True Positive |

---

## 2. Executive Summary

A targeted port scanning attack was detected via the custom Splunk ES correlation rule **"port scanning detection-JAN 26"** on 07 May 2026. The attacker IP `79.124.49.142` originating from **Sofia, Bulgaria** conducted a precision sweep of 18 unique high-range ports (20038–20963) against a single target IP `183.83.51.50` over a 2-hour window. All connection attempts were **denied by the FortiGate firewall**. Threat intelligence from VirusTotal confirmed the IP as malicious (flagged by ADMINUSLabs, SOCRadar, and Fortinet). The attacker belongs to the same `/16` subnet (`79.124.x.x`) as a previously identified persistent threat actor (`79.124.62.122`) — indicating possible coordinated activity from the same threat group.

---

## 3. Detection Details

| Field | Value |
|---|---|
| **Alert Name** | port scanning detection-JAN 26 |
| **Alert Type** | Notable — Correlation Rule |
| **Urgency** | 🟡 Medium |
| **Security Domain** | Network |
| **First Seen** | 2026-05-07 14:24:00 |
| **Last Seen** | 2026-05-07 16:24:00 |
| **Duration** | 2 hours |
| **Total Events** | 18 deny events |
| **Firewall Action** | All DENIED ✅ |

---

## 4. Attack Analysis

### 4.1 Attacker Profile

| Attribute | Details |
|---|---|
| **Source IP** | 79.124.49.142 |
| **Subnet** | 79.124.49.0/24 |
| **ASN** | AS50360 — Tamatiya EOOD |
| **Country** | Bulgaria 🇧🇬 |
| **City** | Sofia |
| **Hostname** | ip-49-142.web1.bg |
| **Domain** | 4vendeta.com |
| **Network Owner** | LIR BG FOOD |
| **Related Threat Actor** | 79.124.62.122 (same /16 subnet — previously investigated) |

### 4.2 Attack Pattern

| Attribute | Details |
|---|---|
| **Target IP** | 183.83.51.50 (single target) |
| **Ports Scanned** | 18 unique ports |
| **Port Range** | 20038 – 20963 (high-range sequential sweep) |
| **Scan Type** | Sequential/Incremental — automated tool |
| **Source Interface** | WAN (external) |
| **Source Port** | 42513 (consistent) |
| **Protocol** | TCP |
| **App Category** | unscanned (non-standard/unrecognized) |

### 4.3 Ports Scanned

```
20038  20092  20097  20190  20303  20310  20319  20459
20466  20613  20626  20672  20694  20771  20807  20914
20958  20963
```

> **Pattern Analysis:** All 18 ports fall in the 20000–21000 range. This is characteristic of a focused sweep targeting a specific service running on non-standard high ports — potentially VoIP (SIP), custom application, or gaming services. This is NOT random scanning — it is a **targeted service discovery attempt**.

---

## 5. Threat Intelligence

### 5.1 VirusTotal — 79.124.49.142

| Vendor | Verdict |
|---|---|
| ADMINUSLabs | 🔴 Malicious |
| SOCRadar | 🔴 Malicious |
| Fortinet | 🔴 Malware |
| alphaMountain.ai | 🟡 Suspicious |
| **Overall** | **3/92 vendors flagged — Confirmed Malicious** |
| Last Analysis | 1 day ago |

### 5.2 Cisco Talos — 79.124.49.142

| Field | Value |
|---|---|
| Location | Sofia, Bulgaria |
| Sender IP Reputation | Neutral |
| Web Reputation | Neutral |
| FWD/REV DNS Match | No data |
| Hostname | ip-49-142.web1.bg |
| Domain | 4vendeta.com |

### 5.3 Subnet Correlation

> ⚠️ **Critical Finding:** `79.124.49.142` belongs to the same `/16` subnet as `79.124.62.122` — the persistent threat actor identified in **Report 1** (Coordinated Brute Force + DDoS Campaign). Both IPs originate from Bulgaria and use the same ASN range. This strongly suggests **coordinated activity from the same threat group** using different IPs to evade IP-based blocks.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Reconnaissance | T1046 | Network Service Scanning | 18 unique ports scanned on single target |
| Reconnaissance | T1595.001 | Active Scanning — Scanning IP Blocks | Sequential port sweep 20038–20963 |
| Defense Evasion | T1036 | Masquerading | Different IP from same subnet to evade previous block |

---

## 7. SPL Queries Used

**Query 1 — Correlation rule trigger (initial detection):**
```
index=main vendor_product="Fortinet Firewall" vendor_action=deny src_ip=79.124.49.142
```

**Query 2 — Unique ports scanned:**
```
index=main sourcetype=fortigate_traffic src_ip=79.124.49.142
| stats dc(dest_port) as unique_ports values(dest_port) as ports_scanned by src_ip
| sort -unique_ports
```

**Query 3 — Target IP and port breakdown:**
```
index=main sourcetype=fortigate_traffic src_ip=79.124.49.142
| stats count by dest_ip dest_port
| sort -count
```

---

## 8. Recommended Actions

### Immediate Actions 🔴
- Block IP **79.124.49.142** on all firewall rules permanently
- Block entire subnet **79.124.0.0/16** — same threat group as previous attacker
- Investigate target IP **183.83.51.50** — verify what service is running on high ports 20000+
- Add `79.124.49.142` to threat intelligence blocklist

### Short Term Actions 🟡
- Review all traffic from `79.124.x.x` range in last 30 days for additional scan activity
- Implement geo-blocking for Bulgaria if no legitimate business traffic expected
- Add correlation rule to detect sequential high-port scanning patterns specifically

### Long Term Actions 🟢
- Update port scanning detection rule threshold to catch smaller scans (below 20 unique ports)
- Add subnet-level threat actor tracking to SIEM
- Implement automated IP block via Adaptive Response when VirusTotal score > 2/92

---

## 9. Conclusion

A precision targeted port scanning attack from Bulgarian IP `79.124.49.142` was successfully detected by the custom Splunk ES correlation rule and confirmed as a **True Positive**. The firewall blocked all 18 attempts. Threat intelligence confirmed the IP as malicious across multiple vendors. The attacker's subnet overlap with a previously investigated persistent threat actor (`79.124.62.122`) indicates coordinated activity from the same threat group. Immediate IP and subnet blocking is recommended along with investigation of the targeted service on `183.83.51.50`.

---

## 📸 Evidence

- Splunk ES Incident Review — alert fired (port scanning detection-JAN 26)
- Raw event search — 18 deny events from 79.124.49.142
- SPL Statistics — 18 unique ports, all targeting 183.83.51.50
- VirusTotal — 3/92 malicious (ADMINUSLabs, SOCRadar, Fortinet)
- Cisco Talos — Sofia, Bulgaria, hostname ip-49-142.web1.bg

---

## 🛠️ Tools Used

- Splunk Enterprise Security (ES) — Detection & Investigation
- SPL (Search Processing Language) — Log Analysis
- VirusTotal — IP Reputation
- Cisco Talos — Threat Intelligence
- FortiGate Firewall Logs — Traffic Evidence

## 📫 Connect

- LinkedIn: linkedin.com/in/dineshtl
- GitHub: github.com/Dineshtl
- Email: dineshtl821@gmail.com
