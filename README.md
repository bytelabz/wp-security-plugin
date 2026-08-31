# AAA Bytelabz Security

A single-file WordPress hardening plugin. It locks user creation and privilege
changes to real administrators, blocks public registration, guards against
privilege escalation, controls REST and XML-RPC exposure, blocks author
enumeration, protects the uploads directory, and runs a daily integrity scan —
reporting everything in one email a day, or none at all.

- **File:** `wp-content/plugins/aaa-site-security.php`
- **Version:** 2.6.1
- **Requires:** WordPress 5.6+, PHP 7.4+
- **Optional:** WooCommerce, Contact Form 7 (both auto-detected)

---

## Contents

1. [Installation](#1-installation)
2. [First-run checklist](#2-first-run-checklist)
3. [Configuration reference](#3-configuration-reference)
4. [What each module does](#4-what-each-module-does)
5. [Alerting and the daily digest](#5-alerting-and-the-daily-digest)
6. [Admin screens](#6-admin-screens)
7. [WooCommerce notes](#7-woocommerce-notes)
8. [Recovery: getting back in](#8-recovery-getting-back-in)
9. [Troubleshooting](#9-troubleshooting)
10. [What this plugin does not protect against](#10-what-this-plugin-does-not-protect-against)
11. [Data stored](#11-data-stored)
12. [Uninstalling](#12-uninstalling)

---

## 1. Installation

1. Upload `aaa-site-security.php` to `wp-content/plugins/`.
2. **Delete any earlier copy** of this code — an older version of the file, or
   the original hardening block in your theme's `functions.php`. Two copies
   active at once causes a fatal `cannot redeclare function` error.
3. Activate it under **Plugins**.

### Why the file name starts with `aaa-`

WordPress loads active plugins in alphabetical order. The `aaa-` prefix puts
this file first, so its guards register before any other plugin runs. Renaming
it to something later in the alphabet weakens it. If your host lets you write
to `wp-content/mu-plugins/`, putting it there is better still — but most shared
hosts (Hostinger included) symlink that directory to their own files.

### Upgrading

Overwrite the file. Do **not** deactivate first. The database table and any new
scheduled jobs are created automatically on the next page load, front-end or
admin, whichever comes first.

---

## 2. First-run checklist

Do these in order. Steps 1–3 take a minute and prevent the two lockouts that
are actually possible.

1. **Add your own IP to the lockout allowlist.** If your host sits behind a
   proxy and `BLZ_TRUST_PROXY` is wrong, every visitor shares one IP address
   and five failed logins locks out the entire world.

   ```php
   define( 'BLZ_LOGIN_IP_ALLOWLIST', array( '203.0.113.42' ) );
   ```

2. **Set the alert address** if it differs from the site admin email:

   ```php
   define( 'BLZ_ALERT_EMAIL', 'you@example.com' );
   ```

3. **If you use WooCommerce shop managers**, exempt that role or they lose the
   ability to manage customers:

   ```php
   define( 'BLZ_ROLE_CAP_EXEMPT', array( 'administrator', 'shop_manager' ) );
   ```

4. **Test a guest checkout end to end** if this is a store. This is the single
   most important test; nothing else matters if orders stop.
5. **Visit Tools → User Audit.** Confirm the event log renders. Review the
   administrator list and the "non-admin accounts holding privileged
   capabilities" table — on a previously compromised site, that is where a
   leftover backdoor account shows up.
6. **Press "Send digest now"** once, to confirm mail actually leaves your
   server. An alerting system you have never tested is not an alerting system.
7. **Leave `BLZ_LOGIN_SLUG` empty for now.** Enable it later, if at all — see
   the warning in the configuration table.

---

## 3. Configuration reference

Every setting is a PHP constant. Edit them in the `CONFIG` block at the top of
the plugin file, or define them in `wp-config.php` — values already defined in
`wp-config.php` always win, which is useful when you don't want your settings
overwritten when you update the plugin file.

### Module switches

| Constant | Default | What it does |
|---|---|---|
| `BLZ_ENABLE_CAPTCHA` | `true` | Image CAPTCHA, honeypot and timing trap on login, registration, lost-password and classic WooCommerce forms. Set `false` if you use another CAPTCHA plugin — running two is worse than one. |
| `BLZ_REQUIRE_EMAIL_VERIFICATION` | `true` | New front-end registrations must click an emailed link before they can log in. Admin-created users, WP-CLI and WooCommerce checkout are exempt. |
| `BLZ_SECURITY_SCAN` | `true` | Master switch for the daily integrity scan. |
| `BLZ_CORE_SCAN` | `true` | Compare every core file against the official checksums from api.wordpress.org. Report only; nothing is changed. |
| `BLZ_UPLOADS_SCAN` | `true` | Find executable PHP in `/uploads/` and quarantine it. |

### Login protection

| Constant | Default | What it does |
|---|---|---|
| `BLZ_MAX_LOGIN_ATTEMPTS` | `5` | Failed logins from one IP before it is locked out. |
| `BLZ_LOCKOUT_SECONDS` | `HOUR_IN_SECONDS` | How long that lockout lasts. |
| `BLZ_CAPTCHA_TTL` | `5 * MINUTE_IN_SECONDS` | How long a CAPTCHA challenge stays valid. |
| `BLZ_MIN_FORM_SECONDS` | `2` | A form submitted faster than this is treated as a bot. Raise if you see false positives; lower it to `0` to disable the timing trap. |
| `BLZ_LOGIN_IP_ALLOWLIST` | `array()` | IPs never locked out. **Put your own here.** |
| `BLZ_TRUST_PROXY` | `false` | Trust `X-Forwarded-For` for the visitor's IP. Only set `true` behind a known proxy or CDN such as Cloudflare — the header is trivially spoofed otherwise, letting an attacker evade the lockout by faking a new IP each attempt. |
| `BLZ_CHECKOUT_CAPTCHA_ALWAYS` | `false` | Challenge logged-in customers at checkout too. By default only guests are challenged, since customers already passed one to log in. |

### User lockdown

| Constant | Default | What it does |
|---|---|---|
| `BLZ_ALLOW_CUSTOMER_REGISTRATION` | `false` | `false` means **nobody but a logged-in administrator can create a user**, by any route. Set `true` to reopen public registration — new accounts are still forced to a safe role and escalation is still blocked. |
| `BLZ_PUBLIC_ROLE` | `''` | Role forced on public signups. Empty means `customer` when WooCommerce is active, otherwise `subscriber`. |
| `BLZ_ROLE_CAP_EXEMPT` | `array( 'administrator' )` | Roles permitted to hold administrator-level capabilities. Add `shop_manager` if you use it. |
| `BLZ_LOCK_ROLE_CAPS` | `false` | Strip admin-level capabilities from non-admin roles at read time. **Leave off.** A plugin that re-registers its roles will see the stripped capability missing and re-add it on every request, fighting this filter forever. `map_meta_cap` already denies those capabilities regardless. |
| `BLZ_ALLOW_USER_WRITE` | `false` | Panic switch. `true` allows all user writes again. Troubleshooting only. |

### REST API

| Constant | Default | What it does |
|---|---|---|
| `BLZ_PUBLIC_REST_ROUTES` | `array( '/wc/store/', '/contact-form-7/' )` | Routes anonymous visitors may reach. Everything else requires a login. Matched against the **route**, not the URL, so no query string can fake a match. |
| `BLZ_REST_DENY_ROUTES` | `array()` | Denied even when a prefix above would allow them. `'/wc/store/v1/products/reviews'` is a useful entry if you don't display block-based reviews — it is the only Store API route returning other people's names. |

Remove `/contact-form-7/` if you don't use that plugin. Add nothing else
without checking why: open DevTools → Network on the page that breaks, filter
for `wp-json`, and add only the namespace you actually see.

### Alerting

| Constant | Default | What it does |
|---|---|---|
| `BLZ_ALERT_MODE` | `'digest'` | `'digest'` — one email a day, only on a day with something real. `'immediate'` — email every notice-or-worse event as it happens. `'off'` — never email anything. |
| `BLZ_CRITICAL_IMMEDIATE` | `true` | Critical events email at once even in digest mode. Set `false` to hold everything for the digest. |
| `BLZ_DIGEST_HOUR` | `7` | Hour of day (site time, 0–23) the digest is sent. |
| `BLZ_ALERT_EMAIL` | `''` | Recipient. Empty uses the site admin email. |
| `BLZ_LOG_RETENTION_DAYS` | `10` | Events older than this are deleted nightly. |

`'off'` disables **email only**. Every block, guard, scan and lockout still
runs and every event is still recorded — read Tools → User Audit instead.

### Uploads and files

| Constant | Default | What it does |
|---|---|---|
| `BLZ_BLOCK_PHP_UPLOADS` | `true` | Refuse uploads with an executable extension, including the `shell.php.jpg` double-extension trick. |
| `BLZ_HARDEN_UPLOADS_DIR` | `true` | Write a deny-PHP `.htaccess` into `/uploads/`. Works on Apache and LiteSpeed; inert on nginx, where the rule must go in the server config. |
| `BLZ_UPLOADS_QUARANTINE_DAYS` | `30` | Grace period before a quarantined file is permanently deleted. |
| `BLZ_UPLOADS_PHP_ALLOWLIST` | *(undefined)* | Array of upload-relative paths the scanner should leave alone. Define only if a plugin legitimately keeps a PHP file in `/uploads/`. |

### Miscellaneous

| Constant | Default | What it does |
|---|---|---|
| `BLZ_SHOW_AUTHOR` | `false` | `false` masks author display names on the front end, so a display name matching a real login cannot be harvested. |
| `BLZ_ENABLE_HSTS` | `false` | Send `Strict-Transport-Security`. Only enable when every subdomain is HTTPS-only — this is hard to undo, as browsers cache it. |
| `BLZ_LOGIN_SLUG` | `''` | Secret login URL, e.g. `'my-secret-login'`. Empty means `wp-login.php` behaves normally. **See the warning below.** |

> **On `BLZ_LOGIN_SLUG`:** this is the weakest control in the plugin and the
> only one that has ever caused an outage. It obscures the login URL; it does
> not stop anything. If you enable it, do so in a private window while staying
> logged in elsewhere, so a mistake doesn't lock you out. Set it back to `''`
> to recover.

---

## 4. What each module does

### The wall: user creation

`wp_pre_insert_user_data` fires inside `wp_insert_user()` immediately before the
database insert, on **every** path — `wp_create_user()`, REST, XML-RPC,
WooCommerce, AJAX, and any plugin calling the core API. Unless a logged-in
administrator is doing it, no row is written.

"Administrator" here means the account genuinely holds the `administrator`
**role**, not merely the capability. The classic persistence trick is to bolt
`manage_options` onto a subscriber; a capability-only check would accept that
attacker.

### Privilege escalation

Roles live in the `{prefix}capabilities` user meta, so one guard on the metadata
API covers `set_role()`, `add_role()`, `update_user_meta()` and the REST user
endpoints. `map_meta_cap` separately denies `create_users`, `promote_users`,
`edit_users` and friends to anyone without a real administrator role — so a
plugin that hands those capabilities to an editor gets nowhere.

Writes that change nothing are ignored. WordPress fires these filters *before*
comparing old and new values, so a plugin re-asserting capabilities it already
granted would otherwise look like an attack. (EventON does this 20 times per
page load; it is harmless.)

### Role table

Rewriting `{prefix}user_roles` is how "subscriber, but with `manage_options`"
happens. The guard diffs the incoming table against the raw database value and
only blocks when a non-exempt role **gains** a capability it didn't have.
Routine plugin housekeeping is allowed and logged at info level. When it does
block, the message names the exact `role:capability` and the file responsible.

### Registration

Every public registration switch is forced off at read time — `users_can_register`
and both WooCommerce options — so flipping the database row changes nothing.
`wp-login.php?action=register` returns 403.

### REST and XML-RPC

Anonymous REST access is refused except for allowlisted routes, enforced twice:
once at `rest_authentication_errors` and again at `rest_pre_dispatch`, where the
resolved route is authoritative. User-writing routes require a real
administrator whoever registered them; editing your own profile is still
allowed. The core user endpoints are removed outright.

`xmlrpc.php` returns 403 outright rather than merely disabling authenticated
methods, and the `X-Pingback` header is stripped.

### Author enumeration

`?author=N` is redirected before the canonical redirect can leak the login
slug, author archives 404, author links point home, the users sitemap provider
is removed, and author names are masked on the front end.

### Integrity scan

Runs daily and on demand:

- **Core files** compared against the official MD5 list from api.wordpress.org,
  using core's own `get_core_checksums()` — the same data WP-CLI uses, but
  in-process, so it works on shared hosting with no shell access. **Report
  only**; nothing is modified.
- **Unknown PHP** in `wp-admin` or `wp-includes` — a prime backdoor indicator.
- **Executable PHP in `/uploads/`** is quarantined: moved to
  `uploads/.blz-quarantine/`, renamed, `chmod 000`, logged, and permanently
  deleted after the grace period. Blank `index.php` guard files are correctly
  ignored.

### Self-protection

While active, the plugin refuses to be removed from the active plugin list and
hides its own Deactivate and Delete links. A stolen admin session cannot simply
switch it off. Deleting the **file** still works — that needs real file access,
and it is your recovery route.

---

## 5. Alerting and the daily digest

Events are classified into three severities, and severity decides what reaches
your inbox.

**Critical — emailed immediately** (rate-limited to one per type per hour):

| Event | Meaning |
|---|---|
| `blocked_escalation` | Something tried to grant admin capabilities to a user |
| `blocked_role_edit` | Something tried to grant capabilities in the role table |
| `new_admin_detected` | An administrator appeared that the roster check didn't know about |
| `blocked_self_deactivate` | Something tried to switch this plugin off |
| `backdoor_quarantined` | Executable PHP was found in `/uploads/` |
| `core_files_modified` | Core files don't match the official checksums |
| `unknown_core_files` | Unrecognised PHP in `wp-admin` or `wp-includes` |
| `admin_email_changed` | An administrator's email address changed |
| `site_admin_email_changed` | The site `admin_email` changed |

**Notice — daily digest only:** `blocked_create`, `blocked_rest_users`,
`blocked_upload`, `user_created`, `privilege_granted`, `core_files_missing`,
`core_check_error`.

**Info — recorded, never emailed:** `blocked_register_page`, `role_table_write`,
`public_signup`, `sessions_destroyed`.

The digest groups by event type with counts, first and last seen, and the five
busiest source IPs — so a thousand blocked registration attempts read as one
line. **Nothing is sent on a day with no real attempt.** A silent inbox means a
clean day.

If mail fails, records stay pending and tomorrow tries again. With
`BLZ_ALERT_MODE` set to `'off'`, records also stay pending, so turning alerting
back on later loses nothing.

---

## 6. Admin screens

### Tools → User Audit

- Administrators, with registration dates
- **Non-admin accounts holding privileged capabilities** — check this first on
  a compromised site
- Accounts registered in the last 30 days
- Pending digest, and when the next one goes out
- Event log with severity, hit counts and source IPs
- Buttons: **Send digest now**, **Prune old rows now**, **Clear event log**,
  **Reset administrator baseline**, **Force logout all users**

**Force logout all users** deletes every session token on the site. Changing
passwords does *not* evict an attacker who already holds a valid auth cookie;
this does. Use it once after any suspected compromise. It logs you out too.

**Reset administrator baseline** tells the roster check that the current list of
administrators is the correct one. Use it after you legitimately add or remove
an admin.

### Tools → Security Scan

Last scan results, a **Scan now** button, and the quarantine list with the date
each file was quarantined and when it will be deleted.

---

## 7. WooCommerce notes

**Logins and purchases are unaffected.** Existing customers log in normally,
guest checkout completes normally, orders and saved addresses are untouched.

**New customer registration is blocked by default.** The My Account
registration form and the "Create an account?" checkbox at checkout are both
disabled. If your store needs self-service accounts:

```php
define( 'BLZ_ALLOW_CUSTOMER_REGISTRATION', true );
```

New accounts are then forced to the `customer` role, and escalation is still
blocked — which is the part that matters.

**Block checkout:** the newer block-based Cart and Checkout use the Store API
at `/wp-json/wc/store/v1/`, which is allowlisted by default. Two consequences:

- Guest checkout works out of the box.
- The CAPTCHA does **not** appear on block checkout. `woocommerce_after_order_notes`
  and `woocommerce_after_checkout_validation` are classic-checkout hooks that
  the Store API never fires. Nothing breaks; there is simply no challenge
  there. The Store API equivalent is
  `woocommerce_store_api_checkout_update_order_from_request`.

**Shop managers** need `BLZ_ROLE_CAP_EXEMPT` extended, or they lose customer
management — see the first-run checklist.

---

## 8. Recovery: getting back in

Ordered from least to most disruptive.

| Situation | Fix |
|---|---|
| Locked out by failed logins | Wait for `BLZ_LOCKOUT_SECONDS`, or add your IP to `BLZ_LOGIN_IP_ALLOWLIST` |
| Secret login URL misbehaving | Set `BLZ_LOGIN_SLUG` back to `''` |
| Can't create a user you need | Temporarily set `BLZ_ALLOW_USER_WRITE` to `true` |
| CAPTCHA locking you out | Add `define( 'BYPASS_CAPTCHA', true );` to `wp-config.php` — disables the CAPTCHA only, nothing else |
| Anything else, or a white screen | **Rename or delete the plugin file** in your host's File Manager |

Renaming the file always works and needs no database access. That is why
deactivation from wp-admin is blocked but file removal is not: an attacker with
a stolen session has the former and not the latter.

---

## 9. Troubleshooting

**"The `wp_blz_events` table could not be created"**
Your database user lacks `CREATE` privilege. Events fall back to a capped
option row (120 records) and **every security control keeps running** — only
log depth is reduced. Creation is retried every 12 hours; the exact database
error is in `uploads/.blz-quarantine/scan.log`.

**No digest arriving**
Press **Send digest now** in Tools → User Audit. If it reports "nothing
pending", there was genuinely nothing to send. If it claims to send but nothing
arrives, `wp_mail` is failing — install an SMTP plugin. WP-Cron only runs when
someone visits the site, so a very quiet site may send late.

**Block cart or checkout broken**
Open DevTools → Network, filter for `wp-json`, and check which namespace is
being refused. Add it to `BLZ_PUBLIC_REST_ROUTES`.

**A plugin can't create users**
That is the plugin working as designed against the wall. Decide whether it
should be allowed; if so, `BLZ_ALLOW_USER_WRITE` is the blunt answer, but
consider whether you need that plugin.

**Repeated `role_table_write` entries in the log**
Normal. Some plugins re-register their roles on every request. The entry names
the responsible file. It is info-level and never emailed. (EventON's
`eventon_init_caps()` is a known example — it grants its own capabilities to
the administrator role and is harmless.)

**Fatal "cannot redeclare function"**
Two copies of this code are active. Remove the old plugin file or the block in
your theme's `functions.php`.

---

## 10. What this plugin does not protect against

Stated plainly, because a security tool that overstates itself is worse than
none.

- **Direct database writes.** A backdoor running `$wpdb->insert()` against
  `wp_users` bypasses every hook here. The daily roster check will *report* a
  new administrator; nothing prevents it.
- **`wp-content/plugins` and `themes` are not scanned.** Only core and
  `/uploads/`. On a previously compromised site that is the most likely place
  for injected code.
- **A vulnerable plugin's own AJAX endpoints** can still do damage that isn't
  user creation.
- **Compromised hosting or database credentials.** Nothing at the application
  layer helps.
- **A stolen active administrator session** can still do most things an
  administrator can do. It cannot silently deactivate this plugin, and its
  actions are logged and alerted.

If you have actually been breached, the highest-value work is finding the entry
point, rotating the salts in `wp-config.php`, and pressing **Force logout all
users** — not adding more code.

---

## 11. Data stored

**Database table** `{prefix}blz_events` — security events, bucketed by event
type + IP + hour with a hit counter, so a bot hitting a blocked endpoint 50,000
times produces 24 rows a day rather than 50,000. Pruned nightly to
`BLZ_LOG_RETENTION_DAYS`.

**Options** (none autoloaded): `blz_db_version`, `blz_known_admins`,
`blz_scan_report`, `blz_scan_ack`, `blz_quarantine`, `blz_events_fallback`
(only when the table is unavailable).

**Files:** `uploads/.blz-quarantine/` holds `scan.log` (rotated at 2 MB, one
previous file kept) and quarantined files. The directory carries a deny-all
`.htaccess`; the scanner never touches it.

**Scheduled jobs:** `blz_daily_security_scan`, `blz_daily_user_audit`,
`blz_daily_digest`, `blz_daily_prune`.

No data leaves your server. The only outbound request is to api.wordpress.org
for official core checksums.

---

## 12. Uninstalling

1. Delete the plugin file.
2. Drop the table `{prefix}blz_events` — WordPress will not do this for you.
3. Optionally delete the `blz_*` options listed above.
4. Optionally delete `wp-content/uploads/.blz-quarantine/`. **Check its contents
   first** — anything in there was quarantined as a suspected backdoor.
5. Remove the deny-PHP block marked `AAA Site Security` from
   `wp-content/uploads/.htaccess`, or leave it; it is good hygiene regardless.

Scheduled jobs disappear on their own once their hooks no longer exist.
