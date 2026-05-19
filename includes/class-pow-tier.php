<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Adaptive PoW tiering — port of pow_tier.php.
 * Uses APCu when available, WordPress transients as fallback.
 */
class Pow_Shield_Tier {

    const TTL_BURST = 60;
    const TTL_FAILS = 900;
    const TTL_TRUST = 86400;

    // ── state storage ──────────────────────────────────────────────────────────

    private static function apcu_ok(): bool {
        return function_exists( 'apcu_fetch' ) && (bool) ini_get( 'apc.enabled' );
    }

    private static function state_get( string $key ): ?array {
        if ( self::apcu_ok() ) {
            $ok = false;
            $v  = apcu_fetch( 'pows_' . $key, $ok );
            return ( $ok && is_array( $v ) ) ? $v : null;
        }
        $v = get_transient( 'pows_' . md5( $key ) );
        return is_array( $v ) ? $v : null;
    }

    private static function state_set( string $key, array $val, int $ttl ): void {
        $val['_exp'] = time() + $ttl;
        if ( self::apcu_ok() ) {
            apcu_store( 'pows_' . $key, $val, $ttl );
            return;
        }
        set_transient( 'pows_' . md5( $key ), $val, $ttl );
    }

    public static function state_bump( string $key, int $ttl, string $field = 'n' ): int {
        $v = self::state_get( $key );
        if ( $v && isset( $v['_exp'] ) && (int) $v['_exp'] < time() ) $v = null;
        $n = (int) ( $v[ $field ] ?? 0 );
        $n++;
        self::state_set( $key, [ $field => $n ], $ttl );
        return $n;
    }

    public static function state_read_int( string $key, string $field = 'n' ): int {
        $v = self::state_get( $key );
        if ( ! $v ) return 0;
        if ( isset( $v['_exp'] ) && (int) $v['_exp'] < time() ) return 0;
        return (int) ( $v[ $field ] ?? 0 );
    }

    // ── client IP ──────────────────────────────────────────────────────────────

    public static function client_ip(): string {
        $ip = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
        return $ip !== '' ? $ip : '0.0.0.0';
    }

    // ── heuristics ────────────────────────────────────────────────────────────

    public static function hits_bot_paths(): bool {
        $uri = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
        foreach ( [ '/.env', '/xmlrpc.php', '/phpmyadmin', '/.git', '/server-status' ] as $p ) {
            if ( stripos( $uri, $p ) !== false ) return true;
        }
        return false;
    }

    public static function risk_score( string $ip ): int {
        $score = 0;

        $burst = self::state_bump( "pow:burst:$ip", self::TTL_BURST );
        if ( $burst > 30 ) $score += 20;
        if ( $burst > 80 ) $score += 35;

        $fails = self::state_read_int( "pow:fails:$ip" );
        if ( $fails >= 3  ) $score += 25;
        if ( $fails >= 10 ) $score += 45;

        if ( self::hits_bot_paths() ) $score += 25;

        $trust = self::state_read_int( "pow:trust:$ip" );
        if ( $trust > 0 ) $score -= 40;

        return max( 0, min( 100, $score ) );
    }

    public static function tier_from_score( int $score ): int {
        if ( $score >= 80 ) return 3;
        if ( $score >= 50 ) return 2;
        if ( $score >= 20 ) return 1;
        return 0;
    }

    public static function bits_for_tier( int $tier ): int {
        return match ( $tier ) {
            0       => 18,
            1       => 20,
            2       => 22,
            default => 24,
        };
    }

    public static function message_for_tier( int $tier ): array {
        return match ( $tier ) {
            0       => [ "Verifying your session\u{2026}",          "Quick integrity check. No CAPTCHA, no tracking." ],
            1       => [ "Checking your browser\u{2026}",           "A lightweight proof-of-work check to deter scrapers." ],
            2       => [ "Running an integrity check\u{2026}",      "Extra verification due to unusual traffic patterns." ],
            default => [ "Checking for clanker-grade automation\u{2026}", "This helps keep the site usable for humans." ],
        };
    }

    public static function mark_trusted( string $ip ): void {
        self::state_set( "pow:trust:$ip", [ 'n' => 1 ], self::TTL_TRUST );
        self::state_set( "pow:fails:$ip", [ 'n' => 0 ], self::TTL_FAILS );
    }

    public static function mark_failed( string $ip ): void {
        self::state_bump( "pow:fails:$ip", self::TTL_FAILS );
    }
}
