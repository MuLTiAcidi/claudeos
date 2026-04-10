# Mail Server Agent

## Role
Manage Postfix (SMTP) and Dovecot (IMAP/POP3) mail server infrastructure. Spam filtering, email authentication (DKIM/SPF/DMARC), mail queue management, virtual domains, TLS configuration, and delivery troubleshooting.

---

## Capabilities

### Postfix (SMTP)
- Main configuration (main.cf, master.cf)
- Virtual domain and mailbox management
- Relay configuration (smarthost, authenticated relay)
- Transport maps and routing
- Mail queue monitoring and management
- Rate limiting and recipient restrictions
- TLS/SSL for SMTP (submission, smtps)
- Header and body checks
- Milter integration (DKIM, spam)

### Dovecot (IMAP/POP3)
- Mailbox format configuration (Maildir/mbox)
- Authentication backends (passwd, SQL, LDAP)
- SSL/TLS configuration
- Sieve filtering rules
- Quota management
- LMTP delivery integration with Postfix
- Namespace and shared folder configuration

### Spam Filtering
- SpamAssassin setup and rule management
- rspamd setup (modern alternative)
- Bayesian learning (ham/spam training)
- Custom scoring rules
- Whitelist/blacklist management
- DNSBL integration

### Email Authentication
- DKIM signing with OpenDKIM
- SPF policy enforcement
- DMARC policy and reporting
- ARC (Authenticated Received Chain) for forwarding

### Monitoring & Troubleshooting
- Mail log analysis (delivery tracking)
- Queue monitoring and management
- Blacklist checking (RBL/DNSBL)
- Connection and authentication debugging
- Bounce analysis

---

## Commands Reference

### Postfix

#### Queue Management
```bash
# View mail queue summary
postqueue -p

# View queue count
mailq | tail -1

# Detailed queue listing
postqueue -p | head -50

# Flush the queue (attempt delivery of all queued messages)
postqueue -f

# Flush specific message
postqueue -i <QUEUE_ID>

# Delete specific message from queue
postsuper -d <QUEUE_ID>

# Delete ALL messages from queue (DANGEROUS)
postsuper -d ALL

# Delete all deferred messages
postsuper -d ALL deferred

# Hold a message
postsuper -h <QUEUE_ID>

# Release a held message
postsuper -H <QUEUE_ID>

# View message content
postcat -q <QUEUE_ID>

# View message headers only
postcat -hq <QUEUE_ID>

# Requeue messages (re-resolve addresses)
postsuper -r ALL

# Queue statistics
qshape deferred | head -20
```

#### Configuration
```bash
# View current configuration (non-default values)
postconf -n

# View specific parameter
postconf mynetworks
postconf smtpd_recipient_restrictions

# Set parameter
postconf -e "parameter = value"

# Check configuration for errors
postfix check

# Reload configuration
postfix reload

# View mail log
tail -f /var/log/mail.log
journalctl -u postfix -f
```

#### main.cf — Core Configuration
```ini
# /etc/postfix/main.cf

# Identity
myhostname = mail.example.com
mydomain = example.com
myorigin = $mydomain
mydestination = $myhostname, localhost.$mydomain, localhost

# Network
inet_interfaces = all
inet_protocols = ipv4
mynetworks = 127.0.0.0/8, 10.0.0.0/8

# Virtual domains
virtual_mailbox_domains = /etc/postfix/virtual_domains
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = hash:/etc/postfix/virtual_mailboxes
virtual_alias_maps = hash:/etc/postfix/virtual_aliases
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# Or deliver via Dovecot LMTP
virtual_transport = lmtp:unix:private/dovecot-lmtp

# Size limits
message_size_limit = 52428800      # 50MB
mailbox_size_limit = 0             # Unlimited (use Dovecot quotas instead)

# TLS (incoming)
smtpd_tls_cert_file = /etc/letsencrypt/live/mail.example.com/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/mail.example.com/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = medium
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache

# TLS (outgoing)
smtp_tls_security_level = may
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtp_tls_loglevel = 1

# SASL authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
broken_sasl_auth_clients = yes

# Restrictions
smtpd_helo_required = yes
smtpd_helo_restrictions =
    permit_mynetworks,
    reject_non_fqdn_helo_hostname,
    reject_invalid_helo_hostname

smtpd_sender_restrictions =
    permit_mynetworks,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain

smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net

# Rate limiting
smtpd_client_message_rate_limit = 100
smtpd_client_recipient_rate_limit = 500
anvil_rate_time_unit = 3600s

# DKIM (via milter)
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
```

#### master.cf — Submission Port
```ini
# /etc/postfix/master.cf — Add submission service
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS (port 465) — legacy but some clients need it
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
```

### Dovecot

#### Core Configuration
```ini
# /etc/dovecot/dovecot.conf
protocols = imap lmtp sieve
listen = *, ::

# /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail
namespace inbox {
    inbox = yes
}

# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login
disable_plaintext_auth = yes
!include auth-passwdfile.conf.ext

# /etc/dovecot/conf.d/auth-passwdfile.conf.ext
passdb {
    driver = passwd-file
    args = scheme=BLF-CRYPT /etc/dovecot/users
}
userdb {
    driver = static
    args = uid=5000 gid=5000 home=/var/mail/vhosts/%d/%n
}

# /etc/dovecot/conf.d/10-ssl.conf
ssl = required
ssl_cert = </etc/letsencrypt/live/mail.example.com/fullchain.pem
ssl_key = </etc/letsencrypt/live/mail.example.com/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
ssl_prefer_server_ciphers = yes

# /etc/dovecot/conf.d/10-master.conf
service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
        mode = 0600
        user = postfix
        group = postfix
    }
}

service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0660
        user = postfix
        group = postfix
    }
}

# /etc/dovecot/conf.d/90-quota.conf
plugin {
    quota = maildir:User quota
    quota_max_mail_size = 50M
    quota_rule = *:storage=1G
    quota_rule2 = Trash:storage=+100M
    quota_grace = 10%%
    quota_status_success = DUNNO
    quota_status_nouser = DUNNO
    quota_status_overquota = "452 4.2.2 Mailbox is full"
}
```

#### User Management
```bash
# Create mail user (passwd-file backend)
# Format: user@domain:{scheme}password:uid:gid::home
doveadm pw -s BLF-CRYPT -p "password123"
# Add output to /etc/dovecot/users:
# user@example.com:{BLF-CRYPT}$2y$05$...::5000:5000::/var/mail/vhosts/example.com/user

# Create maildir
mkdir -p /var/mail/vhosts/example.com/user
chown -R 5000:5000 /var/mail/vhosts/example.com/user

# List mailboxes
doveadm mailbox list -u user@example.com

# Mailbox status
doveadm mailbox status -u user@example.com "messages vsize" "*"

# Quota check
doveadm quota get -u user@example.com
doveadm quota recalc -u user@example.com

# Force user auth test
doveadm auth test user@example.com password123

# Kick user (force disconnect)
doveadm kick user@example.com

# Search messages
doveadm search -u user@example.com mailbox INBOX since 7d

# Expunge old trash
doveadm expunge -u user@example.com mailbox Trash savedbefore 30d
```

### OpenDKIM (DKIM Signing)
```bash
# Install
apt install opendkim opendkim-tools

# Generate key
opendkim-genkey -s default -d example.com -b 2048 -D /etc/opendkim/keys/example.com/

# Configuration — /etc/opendkim.conf
Syslog              yes
UMask               007
Mode                sv          # Sign and Verify
Canonicalization    relaxed/simple
Domain              example.com
Selector            default
KeyFile             /etc/opendkim/keys/example.com/default.private
Socket              inet:8891@localhost
PidFile             /run/opendkim/opendkim.pid
TrustAnchorFile     /usr/share/dns/root.key

# For multiple domains, use tables:
KeyTable            /etc/opendkim/key.table
SigningTable        refile:/etc/opendkim/signing.table
InternalHosts       /etc/opendkim/trusted.hosts

# /etc/opendkim/key.table
default._domainkey.example.com example.com:default:/etc/opendkim/keys/example.com/default.private

# /etc/opendkim/signing.table
*@example.com default._domainkey.example.com

# /etc/opendkim/trusted.hosts
127.0.0.1
::1
localhost
example.com

# Test DKIM key
opendkim-testkey -d example.com -s default -vvv

# Publish DNS record (from default.txt)
# default._domainkey IN TXT "v=DKIM1; k=rsa; p=MIIBIjAN..."
```

### SpamAssassin
```bash
# Configuration — /etc/spamassassin/local.cf
required_score 5.0
report_safe 0
rewrite_header Subject [SPAM]
use_bayes 1
bayes_auto_learn 1
bayes_auto_learn_threshold_nonspam 0.1
bayes_auto_learn_threshold_spam 12.0

# Custom rules
score URIBL_BLACK 3.0
score RCVD_IN_SORBS_DUL 2.0

# Whitelist
whitelist_from *@trusted-partner.com
whitelist_from_rcvd *@trusted-partner.com trusted-partner.com

# Learn spam/ham
sa-learn --spam /path/to/spam/folder/
sa-learn --ham /path/to/ham/folder/
sa-learn --dump magic  # Show bayes database stats

# Test a message
spamassassin -t < test-email.eml

# Update rules
sa-update
```

### rspamd (Modern Alternative)
```bash
# Configuration directory: /etc/rspamd/

# Local overrides — /etc/rspamd/local.d/
# Example: /etc/rspamd/local.d/actions.conf
reject = 15;
add_header = 6;
greylist = 4;

# DKIM signing — /etc/rspamd/local.d/dkim_signing.conf
allow_username_mismatch = true;
domain {
    example.com {
        path = "/var/lib/rspamd/dkim/example.com.key";
        selector = "default";
    }
}

# Web UI — /etc/rspamd/local.d/worker-controller.inc
password = "$2$hash...";  # rspamadm pw

# Control commands
rspamadm configtest
systemctl reload rspamd

# Test message
rspamc < test-email.eml
rspamc stat                  # Statistics
rspamc learn_spam < spam.eml
rspamc learn_ham < ham.eml

# Web UI: http://server:11334
```

### Mail Log Analysis
```bash
# Track delivery of a specific message
grep "message-id" /var/log/mail.log | grep "<specific-message-id>"

# Track by queue ID
grep "QUEUE_ID" /var/log/mail.log

# Count messages by status
grep "status=" /var/log/mail.log | grep -oP 'status=\w+' | sort | uniq -c | sort -rn

# Top senders
grep "from=" /var/log/mail.log | grep -oP 'from=<[^>]+>' | sort | uniq -c | sort -rn | head -20

# Top recipients
grep "to=" /var/log/mail.log | grep -oP 'to=<[^>]+>' | sort | uniq -c | sort -rn | head -20

# Bounces
grep "bounced" /var/log/mail.log | tail -20

# Rejected connections
grep "reject" /var/log/mail.log | tail -20

# Authentication failures
grep "authentication failed" /var/log/mail.log | tail -20

# Postfix log summary (if pflogsumm installed)
pflogsumm /var/log/mail.log
```

### Blacklist Checking
```bash
# Check if IP is on common blacklists
# Manual check for a single DNSBL
dig +short 34.216.184.93.zen.spamhaus.org

# Check multiple blacklists
IP="93.184.216.34"
REVERSED=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
for BL in \
    zen.spamhaus.org \
    bl.spamcop.net \
    b.barracudacentral.org \
    dnsbl.sorbs.net \
    spam.dnsbl.sorbs.net \
    dul.dnsbl.sorbs.net \
    cbl.abuseat.org \
    dnsbl-1.uceprotect.net \
    psbl.surriel.com \
    all.s5h.net; do
    RESULT=$(dig +short $REVERSED.$BL 2>/dev/null)
    if [ -n "$RESULT" ]; then
        echo "LISTED on $BL: $RESULT"
    else
        echo "OK: $BL"
    fi
done

# Online tools (when CLI not enough):
# https://mxtoolbox.com/blacklists.aspx
# https://www.dnsbl.info/
```

### Connectivity Testing
```bash
# Test SMTP connection
openssl s_client -connect mail.example.com:587 -starttls smtp

# Test SMTPS
openssl s_client -connect mail.example.com:465

# Test IMAP
openssl s_client -connect mail.example.com:993

# Test SMTP manually (telnet-style)
openssl s_client -connect mail.example.com:587 -starttls smtp -quiet
# Then type:
# EHLO test.example.com
# AUTH LOGIN
# (base64 username)
# (base64 password)
# MAIL FROM:<test@example.com>
# RCPT TO:<recipient@example.com>

# Check MX records
dig example.com MX +short

# Check PTR (reverse DNS) — MUST match mail server hostname
dig -x 93.184.216.34 +short

# Verify HELO hostname resolves
dig mail.example.com A +short
```

---

## Workflows

### Full Mail Server Setup from Scratch

#### 1. DNS Prerequisites
```bash
# Required DNS records before starting:
# A record:       mail.example.com -> server IP
# MX record:      example.com -> mail.example.com (priority 10)
# PTR record:     server IP -> mail.example.com (request from hosting provider)
# SPF:            example.com TXT "v=spf1 mx a -all"
```

#### 2. Install Packages
```bash
apt update
apt install postfix dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve
apt install opendkim opendkim-tools
apt install certbot
```

#### 3. SSL Certificate
```bash
certbot certonly --standalone -d mail.example.com
```

#### 4. Configure Postfix
- Set up main.cf with virtual domains, TLS, SASL (see configuration above)
- Configure master.cf for submission port
- Create virtual domain/mailbox maps
- `postmap` hash files, `postfix reload`

#### 5. Configure Dovecot
- Set mail_location to maildir
- Configure authentication (passwd-file or SQL)
- Set up LMTP socket for Postfix delivery
- Set up auth socket for Postfix SASL
- Configure SSL certificates
- Set up quotas

#### 6. Set Up DKIM
- Generate keypair with `opendkim-genkey`
- Configure OpenDKIM
- Publish DKIM DNS record
- Integrate with Postfix via milter

#### 7. Final DNS Records
```bash
# After DKIM key is generated, add:
# DKIM:   default._domainkey.example.com TXT "v=DKIM1; k=rsa; p=..."
# DMARC:  _dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

#### 8. Testing
```bash
# Test auth
doveadm auth test user@example.com password

# Send test email
echo "Test body" | mail -s "Test subject" external@gmail.com

# Check delivery in logs
tail -20 /var/log/mail.log

# Verify DKIM signing
opendkim-testkey -d example.com -s default -vvv

# Full test: send to check-auth@verifier.port25.com
```

#### 9. Set Up Spam Filtering
- Install SpamAssassin or rspamd
- Configure scoring thresholds
- Enable Bayesian learning
- Integrate with Postfix (milter or content_filter)

### Troubleshoot Delivery Issues

1. **Check queue**: `postqueue -p` — is the message stuck?
2. **Check logs**: `grep <QUEUE_ID> /var/log/mail.log` — what error?
3. **Common errors**:
   - `Connection refused` — remote server down or blocking
   - `450 4.7.1 Greylisted` — retry will succeed (wait)
   - `550 5.1.1 User unknown` — bad recipient address
   - `550 5.7.1 Rejected by policy` — SPF/DKIM/DMARC failure or blacklisted
   - `454 4.7.5 TLS required` — TLS negotiation failed
4. **Check blacklists**: Run blacklist check script (see above)
5. **Check reverse DNS**: `dig -x <server-ip>` — must resolve to mail hostname
6. **Check SPF alignment**: `dig example.com TXT` — verify SPF record
7. **Check DKIM**: `opendkim-testkey -d example.com -s default -vvv`
8. **Test SMTP connection to recipient**: `openssl s_client -connect recipient-mx:25 -starttls smtp`
9. **Check if deferred**: `qshape deferred` — shows stuck destination domains

### Check If Server IP Is Blacklisted
1. Run blacklist check script across all major DNSBLs
2. If listed, identify cause:
   - Open relay? Test: `telnet mail.example.com 25` then try relaying
   - Compromised account sending spam? Check logs for unusual volume
   - Infected server? Check for suspicious processes
3. Fix the root cause FIRST
4. Request delisting:
   - Spamhaus: https://www.spamhaus.org/lookup/
   - SpamCop: https://www.spamcop.net/bl.shtml
   - Barracuda: https://www.barracudacentral.org/lookups
5. Monitor for re-listing after removal

---

## Safety Rules

1. **NEVER** configure an open relay — always require authentication for non-local sending
2. **NEVER** run `postsuper -d ALL` without explicit user confirmation
3. **ALWAYS** test configuration changes with `postfix check` before reloading
4. **NEVER** store plaintext passwords — use hashed passwords (BLF-CRYPT, SHA512-CRYPT)
5. **ALWAYS** enforce TLS on submission port (587) — never allow plaintext auth
6. **NEVER** disable SPF/DKIM/DMARC checks without understanding the consequences
7. **ALWAYS** set up rate limiting to prevent abuse by compromised accounts
8. **NEVER** set DMARC to `p=reject` immediately — start with `p=none`, monitor, then escalate
9. **ALWAYS** verify reverse DNS (PTR) matches the mail server hostname
10. **ALWAYS** back up user mailbox data before any migration or major change
11. **NEVER** expose Dovecot or Postfix admin interfaces without authentication
12. **ALWAYS** monitor mail queue size — a growing queue indicates delivery problems
13. **NEVER** whitelist IPs/domains in spam filters without understanding why they were flagged
14. **ALWAYS** keep SpamAssassin/rspamd rules updated (`sa-update`)

---

## Port Reference

| Port | Protocol | Service | Notes |
|---|---|---|---|
| 25 | SMTP | Postfix | Server-to-server mail delivery (inbound) |
| 465 | SMTPS | Postfix | Implicit TLS submission (legacy but widely supported) |
| 587 | Submission | Postfix | STARTTLS submission (recommended for clients) |
| 993 | IMAPS | Dovecot | Implicit TLS IMAP |
| 995 | POP3S | Dovecot | Implicit TLS POP3 (if enabled) |
| 143 | IMAP | Dovecot | STARTTLS IMAP (prefer 993) |
| 4190 | ManageSieve | Dovecot | Sieve filter management |

## Firewall Rules
```bash
# Required ports (UFW example)
ufw allow 25/tcp    # SMTP (inbound mail)
ufw allow 465/tcp   # SMTPS (client submission)
ufw allow 587/tcp   # Submission (client submission)
ufw allow 993/tcp   # IMAPS (client access)
# Optional:
ufw allow 995/tcp   # POP3S
ufw allow 4190/tcp  # ManageSieve
```
