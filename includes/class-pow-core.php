<?php
declare(strict_types=1);

if (!defined("ABSPATH")) {
    exit();
}

/**
 * Core request interception + REST verify endpoint.
 */
class Pow_Shield_Core
{
    public static function init(): void
    {
        $options = (array) get_option("pow_shield_options", []);
        if (empty($options["enabled"])) {
            return;
        }

        add_action("rest_api_init", [__CLASS__, "register_rest_routes"]);
        add_action("template_redirect", [__CLASS__, "maybe_challenge"], 1);

        // wp-login.php never fires template_redirect — it is a separate entry
        // point that bypasses template-loader.php entirely — so the front-end
        // gate above can never see it. login_init is the equivalent hook there,
        // and it runs before wp-login.php processes any credentials.
        add_action("login_init", [__CLASS__, "maybe_challenge_login"], 0);

        add_action("wp_login_failed", [__CLASS__, "on_login_failed"]);
    }

    /**
     * Feed real WordPress login failures into the adaptive risk engine so
     * an IP grinding through wp-login.php gets a harder PoW tier, even if
     * it's a real browser carrying a valid pass cookie.
     */
    public static function on_login_failed(string $username): void
    {
        Pow_Shield_Tier::mark_failed(Pow_Shield_Tier::client_ip());
    }

    // ── REST endpoint ─────────────────────────────────────────────────────────

    public static function register_rest_routes(): void
    {
        register_rest_route("pow-shield/v1", "/verify", [
            "methods" => \WP_REST_Server::CREATABLE,
            "callback" => [__CLASS__, "rest_verify"],
            "permission_callback" => "__return_true",
        ]);
    }

    public static function rest_verify(
        \WP_REST_Request $request,
    ): \WP_REST_Response {
        $token = (string) ($request->get_param("token") ?? "");
        $counter = (string) ($request->get_param("counter") ?? "");
        $next = Pow_Shield_Verify::safe_rel_url(
            (string) ($request->get_param("next") ?? "/"),
        );

        $ip = Pow_Shield_Tier::client_ip();

        if ($token === "" || $counter === "" || !ctype_digit($counter)) {
            Pow_Shield_Tier::mark_failed($ip);
            return new \WP_REST_Response(
                ["ok" => false, "error" => "bad-input"],
                400,
            );
        }

        [$ok_tok, $tok, $err] = Pow_Shield_Verify::token_parse_and_verify_v2(
            $token,
        );
        if (!$ok_tok || !is_array($tok)) {
            Pow_Shield_Tier::mark_failed($ip);
            return new \WP_REST_Response(
                ["ok" => false, "error" => $err ?: "bad-token"],
                400,
            );
        }

        $bits_i = (int) $tok["bits"];
        $hash_bin = hash("sha256", $token . "." . $counter, true);
        if (!Pow_Shield_Verify::leading_zero_bits_ok($hash_bin, $bits_i)) {
            Pow_Shield_Tier::mark_failed($ip);
            return new \WP_REST_Response(
                ["ok" => false, "error" => "pow"],
                400,
            );
        }

        // Issue pass cookie
        $keys = Pow_Shield_Verify::pow_keys();
        $kid = (string) ($tok["kid"] ?? array_key_first($keys));
        $key = $keys[$kid] ?? reset($keys);
        $options = (array) get_option("pow_shield_options", []);
        $cookie_ttl = (int) ($options["cookie_ttl"] ?? 21600);

        $cookie_val = Pow_Shield_Verify::issue_pass_cookie(
            $kid,
            $key,
            $cookie_ttl,
        );

        // Set the cookie on the root domain (e.g. .transparencyreport.pw)
        // so it is valid for both www. and non-www. This prevents the challenge
        // from re-firing after redirect when www/non-www differ.
        $cookie_host = explode(":", (string) ($_SERVER["HTTP_HOST"] ?? ""))[0];
        $cookie_domain =
            $cookie_host !== ""
                ? "." . ltrim(preg_replace("/^www\./i", "", $cookie_host), ".")
                : "";

        setcookie("abp", $cookie_val, [
            "expires" => time() + $cookie_ttl,
            "path" => "/",
            "domain" => $cookie_domain,
            "secure" => is_ssl(),
            "httponly" => true,
            "samesite" => "Lax",
        ]);

        Pow_Shield_Tier::mark_trusted($ip);

        return new \WP_REST_Response(["ok" => true, "to" => $next], 200);
    }

    // ── request gate ──────────────────────────────────────────────────────────

    public static function maybe_challenge(): void
    {
        if (self::should_skip()) {
            return;
        }

        if (self::has_valid_pass_cookie()) {
            return;
        }

        self::send_challenge();
        // send_challenge() exits
    }

    /**
     * Gate for wp-login.php, reached via login_init because template_redirect
     * does not fire on that entry point. Runs before wp-login.php dispatches
     * its action, so unsolved requests never reach wp_signon() at all.
     */
    public static function maybe_challenge_login(): void
    {
        $options = (array) get_option("pow_shield_options", []);

        $protect_login =
            !array_key_exists("protect_login", $options) ||
            !empty($options["protect_login"]);
        if (!$protect_login) {
            return;
        }

        // Never gate an already-authenticated user. They are by definition not
        // the brute-force traffic being filtered, and locking a live admin out
        // of their own login page is the one failure worth avoiding outright.
        if (is_user_logged_in()) {
            return;
        }

        // The expired-session prompt renders inside an iframe in wp-admin, and
        // the challenge page sends X-Frame-Options: DENY, which would break it.
        if (!empty($_REQUEST["interim-login"])) {
            return;
        }

        // Logging out is not an attack surface and must always succeed.
        $action = isset($_REQUEST["action"])
            ? (string) $_REQUEST["action"]
            : "login";
        if ($action === "logout") {
            return;
        }

        // User-defined excluded paths still take precedence.
        $uri = (string) ($_SERVER["REQUEST_URI"] ?? "");
        $excludes = (array) ($options["exclude_paths"] ?? []);
        foreach ($excludes as $path) {
            $path = trim((string) $path);
            if ($path !== "" && str_contains($uri, $path)) {
                return;
            }
        }

        if (self::has_valid_pass_cookie()) {
            return;
        }

        self::send_challenge();
        // send_challenge() exits
    }

    private static function has_valid_pass_cookie(): bool
    {
        $cookie_val = (string) ($_COOKIE["abp"] ?? "");
        if ($cookie_val === "") {
            return false;
        }

        [$valid] = Pow_Shield_Verify::validate_pass_cookie($cookie_val);
        return (bool) $valid;
    }

    private static function send_challenge(): void
    {
        // Tell every WP caching plugin (SpeedyCache, WP Super Cache, W3TC,
        // WP Rocket, LiteSpeed Cache, etc.) NOT to cache the challenge page.
        // This must be defined before render() outputs anything.
        if (!defined("DONOTCACHEPAGE")) {
            define("DONOTCACHEPAGE", true);
        }
        if (!defined("DONOTCACHEDB")) {
            define("DONOTCACHEDB", true);
        }
        if (!defined("DONOTMINIFY")) {
            define("DONOTMINIFY", true);
        }
        if (!defined("DONOTCDN")) {
            define("DONOTCDN", true);
        }

        $target = self::current_url();
        Pow_Shield_Challenge::render($target);
        // render() exits
    }

    // ── skip logic ────────────────────────────────────────────────────────────

    private static function should_skip(): bool
    {
        // WP admin (includes admin-ajax.php)
        if (is_admin()) {
            return true;
        }

        // WP cron
        if (wp_doing_cron()) {
            return true;
        }

        // RSS/Atom feeds (no JS/cookies)
        if (is_feed()) {
            return true;
        }

        $uri = (string) ($_SERVER["REQUEST_URI"] ?? "");
        $options = (array) get_option("pow_shield_options", []);

        // Login — protected by default (brute-force target). Admins can opt
        // back out to the legacy full-bypass via Settings > PoW Shield.
        $is_login = str_contains($uri, "/wp-login.php");
        $protect_login =
            !array_key_exists("protect_login", $options) ||
            !empty($options["protect_login"]);
        if ($is_login && !$protect_login) {
            return true;
        }

        // Cron (direct URL hit)
        if (str_contains($uri, "/wp-cron.php")) {
            return true;
        }

        // XML-RPC
        if (str_contains($uri, "/xmlrpc.php")) {
            return true;
        }

        // REST API (our verify endpoint is included — it must not be gated)
        $rest_prefix = (string) get_option("permalink_structure")
            ? rest_get_url_prefix()
            : "wp-json";
        if (str_contains($uri, "/" . $rest_prefix . "/")) {
            return true;
        }

        // Only gate GET and HEAD — except wp-login.php, whose actual
        // credential submission arrives as POST and is the thing brute-force
        // tools abuse, so it stays gated (behind the pass cookie) too.
        $method = strtoupper((string) ($_SERVER["REQUEST_METHOD"] ?? "GET"));
        if (!in_array($method, ["GET", "HEAD"], true)) {
            if (!($is_login && $protect_login)) {
                return true;
            }
        }

        // User-defined excluded paths
        $excludes = (array) ($options["exclude_paths"] ?? []);
        foreach ($excludes as $path) {
            $path = trim((string) $path);
            if ($path !== "" && str_contains($uri, $path)) {
                return true;
            }
        }

        return false;
    }

    private static function current_url(): string
    {
        $uri = (string) ($_SERVER["REQUEST_URI"] ?? "/");
        $parsed = parse_url($uri);
        $path = (string) ($parsed["path"] ?? "/");
        $query = (string) ($parsed["query"] ?? "");
        return $path . ($query !== "" ? "?" . $query : "");
    }
}
