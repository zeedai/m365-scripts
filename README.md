# m365-scripts

A collection of PowerShell scripts for Microsoft 365 administration and security auditing.

Built and maintained by [Zahin Memon](https://www.zmemon.com) — Microsoft 365 Architect based in London. Scripts from the field, not from the docs.

---

## Scripts

### 365Audit.ps1 — M365 Security Audit

Connects to your Microsoft 365 tenant via Graph, runs 9 security checks, and generates a colour-coded HTML report on your desktop. Read-only — nothing in the tenant is changed.

**What it checks:**
- MFA registration across all licensed users
- Global Administrator account count
- Legacy authentication (SMTP, IMAP, POP3) — CA policy check + sign-in log query
- Unified audit log status
- Authentication baseline (Security Defaults vs Conditional Access)
- Stale licensed accounts (no sign-in in 90+ days)
- Unassigned paid licences
- SharePoint and OneDrive external sharing configuration
- Guest invitation settings

**Requirements:**
- PowerShell 7+
- Microsoft.Graph module (`Install-Module Microsoft.Graph -Scope CurrentUser`)
- Global Reader role minimum
- SharePoint Administrator role for the external sharing check

**Run it:**
```powershell
& "C:\Path\To\365Audit.ps1"
```

A browser sign-in prompt appears for Graph. The HTML report opens automatically when the script finishes. A timestamped log file lands on your desktop alongside it.

Full write-up and sample output: [cloudadminhub.com](https://www.cloudadminhub.com)

---

## More scripts coming

This repo will grow as new articles go up on [CloudAdminHub](https://www.cloudadminhub.com). Star or watch the repo to get notified.

---

## Licence

MIT — use freely, modify freely, credit appreciated but not required.
