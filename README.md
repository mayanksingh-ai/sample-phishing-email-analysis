# sample-phishing-email-analysis
Task 2 Elevate labs
# Phishing Email Analysis Report

## Task Objective
To analyze a suspicious email and identify phishing indicators such as email spoofing, mismatched URLs, urgent language, and header anomalies.




---


# 🛡️ Phishing Email Analysis Report — Fake Facebook Login

## 📌 Summary

This report analyzes a phishing email impersonating Facebook. The attacker used a lookalike domain (`faceb00k.com`) to lure users into clicking a malicious link. The goal is to harvest Facebook credentials through a spoofed login page.

---

## 📧 Email Metadata

| Field        | Value |
|--------------|-------|
| **Subject**  | Facebook Security Alert: Unusual Login Attempt |
| **From**     | Facebook Security <security@faceb00k.com> |
| **To**       | user@example.com |
| **Date**     | Wed, 6 Aug 2025 08:17:12 -0500 |

---

## 📝 Email Body



Hi,

We detected an unusual login attempt to your Facebook account from a new device on August 6 at 7:12 AM.

Location: Delhi, India
Device: Chrome on Windows

If this was you, you can safely disregard this message.
If not, please secure your account immediately.

👉 Confirm Your Identity: [https://www.faceb00k.com/](https://www.faceb00k.com/)

Thanks,
The Facebook Security Team


## 📂 Email Header



```
Return-Path: [security@faceb00k.com](mailto:security@faceb00k.com)
Received: from mail.fakehost.net (192.0.2.77)
by mailserver.example.com with ESMTP id 74gxDQ56r
for [user@example.com](mailto:user@example.com);
Wed, 6 Aug 2025 08:17:12 -0500
Received-SPF: fail (example.com: domain of faceb00k.com does not designate 192.0.2.77 as permitted sender)
Authentication-Results: mailserver.example.com;
spf=fail smtp.mailfrom=[security@faceb00k.com](mailto:security@faceb00k.com);
dkim=fail header.i=@faceb00k.com;
dmarc=fail (p=REJECT) header.from=faceb00k.com
Message-ID: [alert@faceb00k.com](mailto:alert@faceb00k.com)
Date: Wed, 6 Aug 2025 08:17:12 -0500
From: Facebook Security [security@faceb00k.com](mailto:security@faceb00k.com)
To: [user@example.com](mailto:user@example.com)
Subject: Facebook Security Alert: Unusual Login Attempt
```


---

## 🚨 Indicators of Phishing (IOCs)

| Indicator | Description |
|----------|-------------|
| **Lookalike Domain** | Uses `faceb00k.com` (with two zeroes) to mimic Facebook |
| **SPF/DKIM/DMARC Failures** | Authentication checks fail across all levels |
| **Urgency** | Claims suspicious login to pressure user |
| **Generic Language** | No use of recipient name |
| **Misleading Branding** | Message styled to appear like a real Facebook security alert |
| **Fake Login Link** | URL leads to `https://www.faceb00k.com/` — a spoofed Facebook page |

---

## 🌐 URL Inspection

**Suspicious Link:** `https://www.faceb00k.com/`

- This domain is **designed to visually mimic** `facebook.com`
- Homoglyphs (`0` instead of `o`) used for deception
- May redirect to phishing pages that steal credentials

🔎 **VirusTotal Scan:**  
https://www.virustotal.com/gui/domain/faceb00k.com

| Scan Engine | Result |
|-------------|--------|
| Fortinet    | Phishing |
| Kaspersky   | Malicious |
| ESET        | Phishing |
| BitDefender | Fraudulent |


---

## 🔍 Tools

| Tool | Use Case | URL |
|------|----------|-----|
| Google Header Analyzer | Header parsing | https://toolbox.googleapps.com/apps/messageheader/ |
| MXToolbox | Email auth checks | https://mxtoolbox.com/EmailHeaders.aspx |
| VirusTotal | URL & domain scanning | https://www.virustotal.com |
| WHOIS Lookup | Domain registration check | https://who.is |
| URLScan.io | Live rendering of phishing sites | https://urlscan.io |


---

## ✅ Mitigation Recommendations

- Block the domain `faceb00k.com` at firewall/DNS/email gateway level
- Enforce **SPF, DKIM, and DMARC** with strict policies
- Add banners or external warning labels for emails from outside domains
- Train users to always **hover over links** and verify domains
---

## 📝 Conclusion

This phishing email sample effectively impersonates Facebook using visual tricks, urgency, and a lookalike domain. Without proper technical controls and user awareness, victims may unknowingly submit their credentials. This report demonstrates the importance of layered security: email filtering, user education, and domain monitoring.

---







