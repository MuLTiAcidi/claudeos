# elta.one — Surface Map (Phase 1 + 2)

Date: 2026-04-26
Authorization: User-owned domain (Herolind / EltaHost / Kosovo)

## Domain
- Registrar: NameCheap (since 2014-12-18)
- Registrant org: EltaHost (Kosovo)
- NS: Cloudflare (ray.ns.cloudflare.com / leah.ns.cloudflare.com)
- SPF allows only 103.214.6.202

## Subdomains discovered (active DNS brute)
| Subdomain | IP / CNAME | Likely purpose |
|---|---|---|
| elta.one (apex) | 103.214.6.202 | WordPress (EltaGamingHosting) |
| www.elta.one | 103.214.6.202 | WordPress |
| mail.elta.one | 103.214.6.202 | self-hosted mail |
| ftp/smtp/pop.elta.one | 103.214.6.202 | mail/file services |
| ns1.elta.one | 103.214.6.202 | self-hosted DNS (overridden by CF at registrar) |
| ns2.elta.one | 103.214.6.203 | secondary DNS |
| cpanel.elta.one | 185.179.30.44 | cPanel management |
| client.elta.one | 185.179.30.44 | likely WHMCS client area |
| test.elta.one | 185.203.118.79 | test environment ⚠️ |
| panel.elta.one | 185.203.118.191 | game panel (Pterodactyl?) |
| shop.elta.one | shops.myshopify.com | Shopify storefront |
| store.elta.one | craftingstore.net | Minecraft store |
| account.elta.one | shops.myshopify.com | Shopify customer account |

## IP groups
- **103.214.6.202/.203** — primary infra (WP, mail, DNS)
- **185.179.30.44** — cPanel & client portal
- **185.203.118.79** — test env
- **185.203.118.191** — game panel

## Apex stack (elta.one)
- nginx (no Cloudflare proxy on apex despite CF NS — origin IP exposed)
- WordPress (REST API at /wp-json/, name="EltaGamingHosting")
- PHP (PHPSESSID cookie)
- Theme: **playgard** (gaming-themed WP theme)
- Custom plugins: **playgard-core**, **void-visual-whmcs-element**
- Public plugins detected: elementor, elementor-pro, contact-form-7, monsterinsights, userfeedback, aioseoBrokenLinkChecker, image-optimizer, omapp (OptinMonster?)
