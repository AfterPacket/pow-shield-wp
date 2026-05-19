<?php
declare(strict_types=1);

if (!defined("ABSPATH")) {
    exit();
}

/**
 * Renders the full standalone PoW challenge page and exits.
 * Port of __ab/pow.php — updated to use WP options + REST API verify endpoint.
 */
class Pow_Shield_Challenge
{
    private static function h(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES, "UTF-8");
    }

    private static function is_mobile_ua(): bool
    {
        $ua = strtolower((string) ($_SERVER["HTTP_USER_AGENT"] ?? ""));
        foreach (
            [
                "mobile",
                "android",
                "iphone",
                "ipad",
                "ipod",
                "iemobile",
                "windows phone",
                "opera mini",
                "silk",
                "kindle",
            ]
            as $n
        ) {
            if (str_contains($ua, $n)) {
                return true;
            }
        }
        return false;
    }

    private static function is_privacy_ua(): bool
    {
        return str_contains(
            strtolower((string) ($_SERVER["HTTP_USER_AGENT"] ?? "")),
            "librewolf",
        );
    }

    /**
     * Output the full PoW challenge HTML page and exit.
     *
     * @param string $target  The original URL to redirect back to after the PoW passes.
     */
    public static function render(string $target): void
    {
        $options = (array) get_option("pow_shield_options", []);

        $BITS_MOBILE = (int) ($options["bits_mobile"] ?? 18);
        $BITS_PRIVACY = (int) ($options["bits_privacy"] ?? 16);
        $CHALLENGE_TTL = 120;

        // Tier-based difficulty
        $ip = Pow_Shield_Tier::client_ip();
        $score = Pow_Shield_Tier::risk_score($ip);
        $tier = Pow_Shield_Tier::tier_from_score($score);
        $bits = Pow_Shield_Tier::bits_for_tier($tier);

        [$headline] = Pow_Shield_Tier::message_for_tier($tier);

        $is_mobile = self::is_mobile_ua();
        $is_privacy = self::is_privacy_ua();

        $BITS = $bits;
        if ($is_mobile) {
            $BITS = min($BITS, $BITS_MOBILE);
        }
        if ($is_privacy) {
            $BITS = min($BITS, $BITS_PRIVACY);
        }

        $challenge_ttl = $CHALLENGE_TTL;
        if ($is_mobile) {
            $challenge_ttl = max(180, $challenge_ttl);
        }
        if ($is_privacy) {
            $challenge_ttl = max(300, $challenge_ttl);
        }

        [$token] = Pow_Shield_Verify::token_make_v2($BITS, $challenge_ttl);

        // Detect actual request scheme (handles Cloudflare / reverse proxies).
        $is_https =
            is_ssl() ||
            (isset($_SERVER["HTTP_X_FORWARDED_PROTO"]) &&
                strtolower($_SERVER["HTTP_X_FORWARDED_PROTO"]) === "https") ||
            (isset($_SERVER["HTTP_CF_VISITOR"]) &&
                str_contains((string) $_SERVER["HTTP_CF_VISITOR"], '"https"'));
        $req_scheme = $is_https ? "https" : "http";

        // Build verify URL from the *current request host* — not home_url().
        // Using home_url() risks a www vs non-www mismatch:
        //   page loads at transparencyreport.pw  (no-www)
        //   home_url() returns www.transparencyreport.pw
        // The fetch crosses origins, the server issues a redirect, and
        // redirect:"follow" silently converts POST→GET → "rest_no_route" 404.
        // Using HTTP_HOST keeps everything same-origin with no redirects.
        $req_host = explode(":", (string) ($_SERVER["HTTP_HOST"] ?? ""))[0];
        $verify_url =
            $req_host !== ""
                ? $req_scheme .
                    "://" .
                    $req_host .
                    "/" .
                    rest_get_url_prefix() .
                    "/pow-shield/v1/verify"
                : set_url_scheme(rest_url("pow-shield/v1/verify"), $req_scheme);

        // CSP origin: still use home_url() host so images/assets load correctly
        // even if wp-content is on a different subdomain than the request host.
        $wp_home = home_url();
        $wp_parsed = parse_url($wp_home);
        $wp_origin = $req_scheme . "://" . ($wp_parsed["host"] ?? $req_host);

        $meme_url = POW_SHIELD_URL . "assets/img/clank.jpg";
        $footer_gif = POW_SHIELD_URL . "assets/img/ahah.gif";

        $mode_label = $is_mobile
            ? "Mobile mode"
            : ($is_privacy
                ? "Privacy mode"
                : "Standard mode");

        // ── headers ───────────────────────────────────────────────────────────
        if (!headers_sent()) {
            header("Content-Type: text/html; charset=utf-8");
            header(
                "Cache-Control: no-store, no-cache, must-revalidate, max-age=0",
            );
            header("CDN-Cache-Control: no-store"); // Cloudflare edge cache
            header("Cloudflare-CDN-Cache-Control: no-store"); // CF override header
            header("Surrogate-Control: no-store"); // generic CDN / Varnish
            header("Pragma: no-cache");
            header("Expires: 0");
            header("Vary: Cookie"); // different response per cookie state
            header("X-Content-Type-Options: nosniff");
            header("X-Frame-Options: DENY");
            header("Referrer-Policy: no-referrer");
            header(
                "Permissions-Policy: geolocation=(), microphone=(), camera=()",
            );
            header(
                "Content-Security-Policy: " .
                    "default-src 'none'; " .
                    "base-uri 'none'; " .
                    "frame-ancestors 'none'; " .
                    "form-action 'none'; " .
                    "img-src 'self' " .
                    $wp_origin .
                    " data:; " .
                    "style-src 'unsafe-inline'; " .
                    "script-src 'unsafe-inline'; " .
                    "connect-src 'self' " .
                    $wp_origin .
                    ";",
            );
        }
        // ── HTML ──────────────────────────────────────────────────────────────
        ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="robots" content="noindex,nofollow,noarchive,nosnippet,noimageindex">
  <title>Checking your browser&#x2026;</title>
  <style>
    :root{
      color-scheme:dark;
      --bg:#070a14;
      --card:rgba(255,255,255,.06);
      --border:rgba(255,255,255,.12);
      --text:#e8eefc;
      --muted:rgba(232,238,252,.72);
      --danger:#fca5a5;
      --ok:#86efac;
      --grad:linear-gradient(90deg,#60a5fa,#a78bfa,#fb7185);
    }
    html,body{height:100%}
    body{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      background:
        radial-gradient(1200px 800px at 20% 15%,rgba(168,85,247,.18),transparent 60%),
        radial-gradient(1000px 700px at 80% 30%,rgba(59,130,246,.14),transparent 65%),
        var(--bg);
      color:var(--text);
      display:flex;align-items:center;justify-content:center;
      padding:20px;
      -webkit-font-smoothing:antialiased;
      text-rendering:geometricPrecision;
    }
    .wrap{width:min(860px,100%)}
    .card{
      background:var(--card);border:1px solid var(--border);
      border-radius:18px;padding:16px;
      box-shadow:0 18px 55px rgba(0,0,0,.35);overflow:hidden;
    }
    .hero{display:flex;flex-direction:column;gap:14px;align-items:center;text-align:center}
    .meme{
      width:100%;border-radius:16px;overflow:hidden;
      border:1px solid rgba(255,255,255,.10);
      background:rgba(0,0,0,.28);
      aspect-ratio:16/9;max-height:380px;
    }
    .meme img{display:block;width:100%;height:100%;object-fit:contain;object-position:center;background:rgba(0,0,0,.15)}
    .title{font-weight:950;letter-spacing:.01em;font-size:20px;margin-top:4px}
    .bar{
      width:min(560px,100%);height:10px;border-radius:999px;
      background:rgba(255,255,255,.10);overflow:hidden;
      border:1px solid rgba(255,255,255,.10);margin-top:6px;
    }
    .bar>div{height:100%;width:0%;background:var(--grad);transition:width .12s ease}
    .row{
      width:min(560px,100%);
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      margin-top:10px;flex-wrap:wrap;
    }
    .chip{
      font-size:12px;color:rgba(255,255,255,.80);
      background:rgba(255,255,255,.06);
      border:1px solid rgba(255,255,255,.10);
      border-radius:999px;padding:6px 10px;
      font-weight:800;letter-spacing:.08em;text-transform:uppercase;
    }
    .muted{color:var(--muted);font-size:13px}
    .danger{color:var(--danger);font-size:13px}
    .ok{color:var(--ok);font-size:13px}
    button{
      appearance:none;border:1px solid rgba(255,255,255,.15);
      background:rgba(255,255,255,.08);color:#fff;font-weight:900;
      border-radius:12px;padding:10px 14px;cursor:pointer;
    }
    button:active{transform:scale(.99)}
    button:focus-visible{outline:2px solid rgba(168,85,247,.85);outline-offset:2px}
    .actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin-top:10px}
    .pow-footer{margin-top:14px;display:flex;justify-content:center}
    .pow-credit{
      display:inline-flex;align-items:center;gap:10px;
      padding:10px 12px;border-radius:999px;
      background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
      box-shadow:0 12px 40px rgba(0,0,0,.25);
      backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
      max-width:100%;
    }
    .pow-credit .gifmark{width:50px;height:52px;flex:0 0 auto;border-radius:6px;object-fit:cover}
    .pow-credit .txt{font-size:12px;color:rgba(232,238,252,.78);white-space:nowrap}
    .pow-credit a{color:rgba(147,197,253,.92);text-decoration:none;font-weight:900}
    .pow-credit a:hover{text-decoration:underline}
    @media(max-width:420px){.pow-credit .txt{font-size:11px;white-space:normal}.pow-credit .gifmark{width:20px;height:20px}}
    @media(prefers-reduced-motion:reduce){.bar>div{transition:none}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">

        <div class="meme" aria-hidden="true">
          <img src="<?= self::h($meme_url) ?>" alt="">
        </div>

        <div class="title"><?= self::h($headline) ?></div>
        <span style="color:var(--muted);font-size:14px;line-height:1.45;max-width:60ch">
          This site uses a lightweight proof-of-work check to reduce abusive traffic.
          It should complete quickly for normal visitors.
        </span>

        <div class="bar" aria-label="Progress"><div id="pbar"></div></div>

        <div class="row">
          <span class="chip" id="modeChip"><?= self::h($mode_label) ?></span>
          <span class="muted" id="etaText">Starting&hellip;</span>
        </div>

        <noscript>
          <div class="danger" style="margin-top:10px">JavaScript is required to continue.</div>
        </noscript>

        <div class="actions">
          <button id="retry" type="button" style="display:none">Retry</button>
        </div>

        <div class="muted" style="margin-top:6px">
          Difficulty: <strong><?= (int) $BITS ?></strong> &bull;
          Challenge TTL: <strong><?= (int) $challenge_ttl ?>s</strong>
        </div>

        <div class="pow-footer" role="contentinfo">
          <div class="pow-credit">
            <img class="gifmark" src="<?= self::h(
                $footer_gif,
            ) ?>" alt="" aria-hidden="true" loading="lazy">
            <span class="txt">
              <center>PoW Shield &bull; Created By&nbsp;
                <a href="https://github.com/AfterPacket" target="_blank" rel="noopener noreferrer nofollow">AfterPacket</a>
              </center>
            </span>
          </div>
        </div>

      </div>
    </div>
  </div>

<script>
(() => {
  const TOKEN      = <?= json_encode($token, JSON_UNESCAPED_SLASHES) ?>;
  const TARGET     = <?= json_encode($target, JSON_UNESCAPED_SLASHES) ?>;
  const VERIFY_URL = <?= json_encode($verify_url, JSON_UNESCAPED_SLASHES) ?>;
  const BITS       = <?= (int) $BITS ?>;

  const pbar  = document.getElementById('pbar');
  const retry = document.getElementById('retry');
  const eta   = document.getElementById('etaText');

  window.addEventListener('pageshow', (e) => { if (e.persisted) location.reload(); });

  function setEta(t, cls) {
    if (!eta) return;
    eta.className  = cls || 'muted';
    eta.textContent = t;
  }

  if (!window.crypto || !crypto.subtle || !window.TextEncoder) {
    setEta("This browser can\u2019t run the check (WebCrypto missing).", "danger");
    retry.style.display = "inline-block";
    retry.onclick = () => location.reload();
    return;
  }

  function hasCookie(name) {
    return document.cookie.split(";").some(c => c.trim().startsWith(name + "="));
  }
  try {
    const secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = "__ab_ct=1; Path=/; SameSite=Lax" + secure;
  } catch {}
  if (!hasCookie("__ab_ct")) {
    setEta("Cookies appear blocked. Enable site cookies to continue.", "danger");
    retry.style.display = "inline-block";
    retry.onclick = () => location.reload();
    return;
  }

  const enc = new TextEncoder();

  function hasLeadingZeroBits(buf, bits) {
    const bytes = new Uint8Array(buf);
    const full  = Math.floor(bits / 8);
    const rem   = bits % 8;
    for (let i = 0; i < full; i++) if (bytes[i] !== 0) return false;
    if (rem === 0) return true;
    return (bytes[full] & (0xFF << (8 - rem))) === 0;
  }

  async function sha256(str) {
    return await crypto.subtle.digest('SHA-256', enc.encode(str));
  }

  async function solve(bits) {
    let counter = 0;
    let lastUI  = performance.now();
    const start = performance.now();
    let warned  = false;

    while (true) {
      counter++;
      const h = await sha256(TOKEN + "." + counter);
      if (hasLeadingZeroBits(h, bits)) return counter;

      const now = performance.now();
      if (now - lastUI > 120) {
        lastUI = now;
        const pct     = Math.min(95, Math.round((Math.log(counter) / Math.log(700000)) * 95));
        pbar.style.width = pct + "%";
        const elapsed = Math.max(0.1, (now - start) / 1000);
        if (!warned && elapsed > 15) {
          warned = true;
          setEta("Still working\u2026 this browser is running in a hardened/slow mode.", "muted");
        } else {
          setEta("Working\u2026 " + elapsed.toFixed(1) + "s", "muted");
        }
        await new Promise(r => setTimeout(r, 0));
      }
      if (counter > 4000000) throw new Error("too-hard");
    }
  }

  async function postSolution(counter) {
    const body = new URLSearchParams();
    body.set("token",   TOKEN);
    body.set("counter", String(counter));
    body.set("next",    TARGET);

    const resp = await fetch(VERIFY_URL, {
      method:      "POST",
      headers:     { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      credentials: "include",
      redirect:    "error",
      cache:       "no-store",
    }).catch(err => { throw new Error("net:" + (err.message || String(err))); });

    const txt = await resp.text().catch(() => "");
    if (!resp.ok) throw new Error("http-" + resp.status + ":" + txt.slice(0, 200));

    try {
      const obj = JSON.parse(txt);
      if (obj && obj.ok && obj.to) return obj.to;
    } catch {}
    return TARGET;
  }

  async function run() {
    try {
      setEta("Working\u2026", "muted");
      const counter = await solve(BITS);

      pbar.style.width = "98%";
      setEta("Verifying\u2026", "muted");

      const to = await postSolution(counter);
      pbar.style.width = "100%";
      setEta("Done. Redirecting\u2026", "ok");
      location.replace(to);

    } catch (e) {
      pbar.style.width = "0%";
      const msg = String(e && e.message || e);

      // Always log the full error + the URL being used so it's easy to debug
      console.error('[PoW Shield] failed:', msg);
      console.error('[PoW Shield] verify URL:', VERIFY_URL);

      if (msg.startsWith("net:")) {
        // fetch() itself threw — mixed content, CORS, or server unreachable
        setEta("Network error reaching verify endpoint. Check browser console (F12).", "danger");
      } else if (msg.startsWith("http-429")) {
        setEta("Rate-limited (429). Wait a moment and retry.", "danger");
      } else if (msg.startsWith("http-403")) {
        setEta("Blocked (403) \u2014 a security plugin or firewall is blocking the verify endpoint.", "danger");
      } else if (msg.startsWith("http-")) {
        const code = msg.split(":")[0].replace("http-", "");
        setEta("Verify returned " + code + " \u2014 open browser console (F12) for details.", "danger");
      } else if (msg === "too-hard") {
        setEta("Challenge exceeded attempt limit. Please retry.", "danger");
      } else {
        setEta("Failed: " + msg.slice(0, 80), "danger");
      }

      retry.style.display = "inline-block";
      retry.onclick = () => location.reload();
    }
  }

  run();
})();
</script>
</body>
</html>
        <?php exit();
    }
}
