# ⚡ PoW Shield — WordPress Plugin

A lightweight **Proof-of-Work gateway** for WordPress. Stops bots, scrapers, and abusive traffic dead in their tracks — no CAPTCHAs, no third-party services, no privacy trade-offs.

Every new visitor's browser silently solves a small SHA-256 puzzle. Humans pass in seconds. Bots burn CPU trying to keep up.

---

## Features

- **No CAPTCHA** — invisible to real users, painful for bots
- **No third-party services** — everything runs on your server
- **Adaptive difficulty** — automatically increases for IPs showing bot-like behaviour
- **Mobile & privacy browser aware** — lower difficulty for mobile UAs and LibreWolf/privacy browsers
- **Signed tokens & cookies** — HMAC-SHA256, not guessable or replayable
- **www / non-www safe** — works correctly regardless of domain configuration or reverse proxy setup
- **Caching plugin compatible** — defines `DONOTCACHEPAGE` and related constants so challenge pages are never cached
- **Cloudflare compatible** — correct `Cache-Control`, `CDN-Cache-Control`, and scheme detection via `HTTP_X_FORWARDED_PROTO` / `HTTP_CF_VISITOR`
- **ModSecurity / WAF friendly** — no unusual request patterns
- **Zero dependencies** — pure PHP 8, no Composer, no npm

---

## Requirements

| | |
|---|---|
| WordPress | 5.9 or later |
| PHP | 8.0 or later |
| Pretty Permalinks | Recommended (REST API works without them too) |

---

## Installation

1. Download or clone this repository into your `wp-content/plugins/` directory:
   ```
   wp-content/plugins/pow-shield-wordpress/
   ```
2. In your WordPress admin go to **Plugins → Installed Plugins** and activate **PoW Shield**.
3. That's it — the challenge is live immediately on all front-end pages.

---

## Settings

Navigate to **Settings → PoW Shield** in your WordPress admin.

### General

| Setting | Default | Description |
|---|---|---|
| Enable PoW Shield | On | Gates all front-end GET/HEAD requests |
| Cookie TTL | 21600 s (6 h) | How long the pass cookie is valid before re-challenging |

### Difficulty

Difficulty is measured in **leading zero bits** required in the SHA-256 hash. Each extra bit doubles the expected work.

| Setting | Default | Range |
|---|---|---|
| Desktop | 20 | 16 – 24 |
| Mobile UA | 18 | 14 – 22 |
| Privacy browsers (LibreWolf etc.) | 16 | 12 – 20 |

The adaptive tier system automatically overrides these values upward for IPs with a high risk score.

### Excluded Paths

One path fragment per line. Any request whose URI contains a listed string skips the challenge entirely.

The following are **always skipped automatically** and do not need to be listed:

- `/wp-admin/` and `admin-ajax.php`
- `/wp-login.php`
- `/wp-cron.php`
- `/xmlrpc.php`
- REST API (`/wp-json/` or your custom REST prefix)
- RSS / Atom feeds
- All non-GET/HEAD methods (POST, PUT, DELETE, etc.)

---

## How It Works

```
1. Visitor hits your site (no abp cookie)
        ↓
2. Plugin renders a standalone challenge page
        ↓
3. Browser JS solves a SHA-256 proof-of-work puzzle
        ↓
4. Solution is POSTed to /wp-json/pow-shield/v1/verify
        ↓
5. Server verifies the solution and issues a signed abp cookie
        ↓
6. Visitor is redirected to the original URL and passes through instantly
   on all subsequent requests until the cookie expires
```

### Adaptive Tier System

The plugin tracks each IP's behaviour and assigns a risk score:

| Trigger | Score |
|---|---|
| > 30 requests in 60 s | +20 |
| > 80 requests in 60 s | +35 |
| ≥ 3 failed verifications | +25 |
| ≥ 10 failed verifications | +45 |
| Probing bot paths (`.env`, `phpMyAdmin`, `.git`, etc.) | +25 |
| Previously trusted (passed PoW) | −40 |

| Score | Tier | Difficulty |
|---|---|---|
| 0 – 19 | 0 (Normal) | 18 bits |
| 20 – 49 | 1 (Elevated) | 20 bits |
| 50 – 79 | 2 (High) | 22 bits |
| 80 – 100 | 3 (Critical) | 24 bits |

State is stored in **APCu** when available, falling back to **WordPress transients**.

---

## Advanced Configuration

### Defining the secret in `wp-config.php` (recommended for production)

By default the plugin generates and stores a random secret in the database on activation. For production you can pin it in `wp-config.php` instead — the database option is ignored while the constant exists:

```php
define( 'POW_SHIELD_SECRET', 'your-64-char-random-hex-string-here' );
```

To support graceful secret rotation without immediately invalidating all existing cookies, you can also define a previous secret:

```php
define( 'POW_SHIELD_SECRET',      'new-secret-here' );
define( 'POW_SHIELD_SECRET_PREV', 'old-secret-here' );
```

Both secrets are tried when validating tokens and cookies. `_PREV` is only ever used for validation, never for issuing new tokens.

### Rotating the secret via the admin UI

Go to **Settings → PoW Shield → Rotate Secret**. The current secret is automatically moved to `pow_shield_secret_prev` so existing valid cookies continue to work until they expire naturally.

---

## Caching Plugin Compatibility

The plugin defines the following constants before rendering the challenge page so that caching plugins skip it:

| Constant | Respected by |
|---|---|
| `DONOTCACHEPAGE` | SpeedyCache, WP Super Cache, W3 Total Cache, WP Rocket, LiteSpeed Cache |
| `DONOTCACHEDB` | W3 Total Cache |
| `DONOTMINIFY` | W3 Total Cache, WP Rocket |
| `DONOTCDN` | LiteSpeed Cache |

> **Important:** If your caching plugin already has a cached copy of a challenge page from before this plugin was installed or updated, clear its cache once manually. After that, the constants handle it going forward.

---

## Cloudflare Compatibility

The plugin is fully compatible with Cloudflare in **default caching mode** (Cloudflare does not cache HTML by default — only static assets).

The challenge response includes:

```
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
CDN-Cache-Control: no-store
Cloudflare-CDN-Cache-Control: no-store
Surrogate-Control: no-store
Vary: Cookie
```

> **If you use a "Cache Everything" Page Rule or Cache Rule**, add an exception to bypass cache when the `abp` cookie is absent, otherwise Cloudflare may serve cached real pages to unverified visitors.

The plugin detects HTTPS correctly behind Cloudflare via `HTTP_X_FORWARDED_PROTO` and `HTTP_CF_VISITOR`, so no extra server configuration is needed.

---

## Troubleshooting

### Challenge keeps re-appearing after passing

Your WordPress `siteurl`/`home` uses a different `www` prefix than the URL visitors actually land on (e.g. WordPress is `www.example.com` but Cloudflare or a server redirect serves `example.com`). The plugin handles this automatically since v1.0.3 by building the verify URL from `HTTP_HOST` and setting the cookie on the root domain (`.example.com`). Make sure you are running v1.0.3 or later.

### "Verify returned 404 — rest_no_route"

The REST API POST is being converted to a GET by a server redirect (www ↔ non-www). Fixed in v1.0.3 by using `HTTP_HOST` for the verify URL so no cross-origin redirect occurs.

### "Network error reaching verify endpoint"

Usually a Content Security Policy mismatch — the verify URL's origin doesn't match the page origin. Fixed in v1.0.2+ by including `home_url()`'s host in the CSP `connect-src` directive alongside `'self'`.

### Challenge page has no progress and fails instantly

Check the browser console (F12). Since v1.0.2 the error message is specific:
- **"Network error"** → CSP or mixed-content block. Check that your WordPress URL scheme matches what visitors see.
- **"Verify returned 4xx"** → The error body is logged to the console. Check for a firewall or security plugin blocking the REST endpoint.

---

## Changelog

### 1.0.3
- Fixed www/non-www re-challenge loop: verify URL now built from `HTTP_HOST` instead of `home_url()`
- Fixed `rest_no_route` 404: changed JS fetch `redirect` from `follow` to `error` to prevent POST→GET conversion on redirects
- Fixed cookie domain: now set to root domain (`.example.com`) so it is valid for both www and non-www

### 1.0.2
- Fixed CSP blocking verify fetch when WordPress `home_url` host differs from the request host
- Added `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`, `Surrogate-Control`, and `Vary: Cookie` headers
- Improved JS error messages — now shows specific HTTP status codes and logs to console

### 1.0.1
- Added `DONOTCACHEPAGE`, `DONOTCACHEDB`, `DONOTMINIFY`, `DONOTCDN` constants to prevent caching plugins from storing the challenge page

### 1.0.0
- Initial release

---

## License

GPL-3.0-or-later — see [LICENSE](https://www.gnu.org/licenses/gpl-3.0.html).

---

*PoW Shield — Created by [AfterPacket](https://github.com/AfterPacket)*
