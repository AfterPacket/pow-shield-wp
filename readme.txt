=== PoW Shield ===
Contributors: afterpacket
Tags: security, bot protection, proof of work, anti-bot, ddos
Requires at least: 5.9
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Lightweight Proof-of-Work (PoW) bot shield for WordPress. No CAPTCHAs, no third-party services.

== Description ==

PoW Shield stops abusive bot traffic by requiring each new visitor's browser to solve a small SHA-256 computational puzzle before accessing your site. Once solved, a signed cookie grants access for the configured TTL — normal visitors complete this invisibly in under a second.

**Key features:**

* Zero CAPTCHA, zero third-party tracking
* Adaptive difficulty — raises the bar automatically for IPs exhibiting bot-like behaviour
* Mobile and privacy-browser aware (lower difficulty for slower devices)
* Signed, HMAC-verified pass cookie (6-hour default TTL)
* wp-login.php is protected by default (GET and POST) to stop brute-force/credential-stuffing bots; toggle available if you need the legacy bypass
* Automatic bypass for wp-admin, REST API, cron, XML-RPC, feeds
* User-configurable excluded paths
* APCu support for high-performance rate tracking; WordPress transients as fallback
* Secret rotation with overlap (old cookies stay valid through the transition)

== Installation ==

1. Upload the `pow-shield` folder to `/wp-content/plugins/`.
2. Activate the plugin in **Plugins > Installed Plugins**.
3. Go to **Settings > PoW Shield** to configure.

For production, add your secret to `wp-config.php`:

  define( 'POW_SHIELD_SECRET', 'your-64-char-random-string' );

== Frequently Asked Questions ==

= Will this break my RSS feed readers? =
No — feed requests are automatically bypassed.

= Will logged-in admin users be challenged? =
No — all requests to wp-admin are automatically bypassed.

= Does this work without Apache / mod_rewrite? =
Yes. Unlike the standalone version, this plugin works at the PHP level via WordPress hooks — no server config required.

= Can I exclude specific pages? =
Yes — add path fragments under Settings > PoW Shield > Excluded Paths.

== Changelog ==

= 1.0.3 =
* wp-login.php is now gated by the PoW challenge by default (both GET and POST), closing a gap where brute-force/credential-stuffing bots hitting wp-login.php directly were never challenged.
* Failed WordPress login attempts now feed the adaptive risk engine, raising PoW difficulty for offending IPs.
* Added "Protect wp-login.php" setting to restore the previous full-bypass behavior if needed.

= 1.0.0 =
* Initial WordPress plugin release, ported from pow-shield-php.
