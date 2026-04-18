# Technique Stats — Win/Loss Tracking

**The pack learns from every hunt. This file tracks what works and what doesn't.**

*Updated after each engagement. The Alpha reads this before choosing attack angles.*

---

## Technique Success Rates

| Technique | Wins | Losses | Rate | Best Target Type |
|-----------|------|--------|------|-----------------|
| GraphQL error-based schema discovery | 1 | 0 | 100% | Crypto exchanges (Bumba) |
| GraphQL PERMS_GUARD bypass | 1 | 0 | 100% | NestJS/Apollo backends |
| CORS with credentials exploitation | 1 | 0 | 100% | Adult platforms (Stripchat) |
| Cognito direct SignUp (captcha bypass) | 1 | 0 | 100% | AWS Cognito apps |
| KYC bypass via API | 1 | 0 | 100% | Crypto exchanges |
| delete_user without confirmation | 1 | 0 | 100% | GraphQL APIs |
| OTP brute-force (no rate limit) | 1 | 0 | 100% | NestJS backends (1win) |
| Conversion order execution | 1 | 0 | 100% | Crypto exchanges |
| ADFS exposure testing | 0 | 1 | 0% | Enterprise (REI) — config exposed but not exploitable |
| S3 bucket enumeration | 0 | 2 | 0% | Enterprise (REI, others) — all access denied |
| XXE via config import | 0 | 1 | 0% | Zabbix — properly mitigated |
| Stored XSS via API | 0 | 1 | 0% | Zabbix — properly escaped |
| Integer overflow on network protocol | 0 | 1 | 0% | Zabbix — max size check |
| CVE exploitation on test instance | 0 | 1 | 0% | NetScaler — prerequisites not met |
| Source code review (PHP) | 0 | 1 | 0% | Zabbix — mature codebase, low-hanging fruit gone |

---

## Target Type Success Rates

| Target Type | Hunts | Findings | Reports | Paid | Avg Payout |
|-------------|-------|----------|---------|------|------------|
| Crypto Exchange | 1 | 13 | 1 | Pending | TBD |
| Adult Platform | 1 | 1 | 1 | Pending | TBD |
| Betting Platform | 1 | 8 | 0 | — | — |
| Enterprise SaaS (Zabbix) | 1 | 0 | 0 | — | — |
| Enterprise Retail (REI) | 1 | 0 | 0 | — | — |
| Network Appliance (NetScaler) | 1 | 0 | 0 | — | — |

---

## Lessons Per Target Type

### Crypto Exchanges (HIGH SUCCESS)
- GraphQL + missing permission guards = gold
- Always test conversion/trading mutations separately from admin mutations
- KYC bypass via API is common when frontend enforces but backend doesn't
- Real crypto deposit on unverified account = undeniable proof

### Adult Platforms (HIGH SUCCESS)
- CORS on tracking/retargeting endpoints = user data theft
- SameSite=None cookies enable cross-origin attacks
- Performer ID → username resolution chains amplify impact
- Sensitivity of data makes even medium bugs high-impact

### Enterprise SaaS (LOW SUCCESS)
- Mature programs (75+ resolved reports) = low-hanging fruit gone
- Source code review needs fuzzing, not just reading
- Need to build and test locally before claiming bugs

### Enterprise Retail (LOW SUCCESS)
- Akamai WAF blocks everything from curl
- ADFS exposure is informational without proven exploitation
- Third-party subdomains get dismissed

---

## How to Use This File

**Before hunting:** Check which techniques work on the target type.
**After hunting:** Update the stats with wins and losses.
**The Alpha reads this** to decide which wolves to deploy first.
