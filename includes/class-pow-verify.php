<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Cryptographic helpers — port of pow-verify.php.
 * Handles token creation/verification and cookie issuance.
 */
class Pow_Shield_Verify {

    // ── base64url helpers ──────────────────────────────────────────────────────

    public static function b64url_enc( string $bin ): string {
        return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
    }

    public static function b64url_dec( string $s ): string {
        $s   = strtr( $s, '-_', '+/' );
        $pad = strlen( $s ) % 4;
        if ( $pad ) $s .= str_repeat( '=', 4 - $pad );
        $out = base64_decode( $s, true );
        return is_string( $out ) ? $out : '';
    }

    public static function hmac_b64( string $data, string $key ): string {
        return self::b64url_enc( hash_hmac( 'sha256', $data, $key, true ) );
    }

    public static function ua_hash_b64(): string {
        $ua = (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        return self::b64url_enc( hash( 'sha256', $ua, true ) );
    }

    // ── key management ────────────────────────────────────────────────────────

    /**
     * Returns ['A' => current_secret, 'B' => prev_secret (if any)].
     * Checks wp-config.php constants first, then WP options.
     */
    public static function pow_keys(): array {
        $cur  = defined( 'POW_SHIELD_SECRET' )      ? POW_SHIELD_SECRET      : (string) get_option( 'pow_shield_secret',      '' );
        $prev = defined( 'POW_SHIELD_SECRET_PREV' )  ? POW_SHIELD_SECRET_PREV : (string) get_option( 'pow_shield_secret_prev', '' );

        $keys = [];
        if ( $cur  !== '' ) $keys['A'] = $cur;
        if ( $prev !== '' ) $keys['B'] = $prev;
        return $keys;
    }

    // ── URL safety ────────────────────────────────────────────────────────────

    public static function safe_rel_url( string $u ): string {
        $u = trim( $u );
        if ( $u === '' || $u[0] !== '/' )                         return '/';
        if ( str_starts_with( $u, '//' ) )                        return '/';
        if ( str_contains( $u, "\r" ) || str_contains( $u, "\n" ) ) return '/';
        return $u;
    }

    // ── challenge token ───────────────────────────────────────────────────────

    public static function token_make_v2( int $bits, int $ttl_seconds ): array {
        $keys = self::pow_keys();
        if ( ! $keys ) throw new \RuntimeException( 'No POW_SHIELD_SECRET configured' );

        $kid = (string) array_key_first( $keys );
        $key = reset( $keys );
        $iat = time();
        $exp = $iat + $ttl_seconds;

        $payload = [
            'v'    => 2,
            'kid'  => $kid,
            'iat'  => $iat,
            'exp'  => $exp,
            'bits' => $bits,
            'salt' => self::b64url_enc( random_bytes( 18 ) ),
            'uah'  => self::ua_hash_b64(),
        ];

        $json = json_encode( $payload, JSON_UNESCAPED_SLASHES );
        if ( ! is_string( $json ) ) throw new \RuntimeException( 'token json fail' );

        $p64 = self::b64url_enc( $json );
        $sig  = self::hmac_b64( $p64, $key );

        return [ $p64 . '.' . $sig, $payload ];
    }

    // ── challenge token verification ──────────────────────────────────────────

    public static function token_parse_and_verify_v2( string $token ): array {
        $parts = explode( '.', $token );
        if ( count( $parts ) !== 2 ) return [ false, null, 'bad-token' ];

        [ $p64, $sig ] = $parts;
        $json = self::b64url_dec( $p64 );
        if ( $json === '' ) return [ false, null, 'bad-payload' ];

        $payload = json_decode( $json, true );
        if ( ! is_array( $payload ) || (int) ( $payload['v'] ?? 0 ) !== 2 ) return [ false, null, 'bad-v' ];

        $kid  = (string) ( $payload['kid'] ?? '' );
        $keys = self::pow_keys();
        if ( ! $keys ) return [ false, null, 'no-secret' ];

        $candidates = [];
        if ( $kid !== '' && isset( $keys[ $kid ] ) ) $candidates[] = $keys[ $kid ];
        foreach ( $keys as $k ) $candidates[] = $k;
        $candidates = array_values( array_unique( $candidates ) );

        $ok_sig = false;
        foreach ( $candidates as $k ) {
            if ( hash_equals( self::hmac_b64( $p64, $k ), $sig ) ) { $ok_sig = true; break; }
        }
        if ( ! $ok_sig ) return [ false, null, 'sig' ];

        $now = time();
        $iat = (int) ( $payload['iat'] ?? 0 );
        $exp = (int) ( $payload['exp'] ?? 0 );
        if ( $exp < $now || $iat > ( $now + 60 ) ) return [ false, null, 'expired' ];

        $uah = (string) ( $payload['uah'] ?? '' );
        if ( $uah === '' || ! hash_equals( $uah, self::ua_hash_b64() ) ) return [ false, null, 'ua-mismatch' ];

        $bits = (int) ( $payload['bits'] ?? 0 );
        if ( $bits < 16 || $bits > 24 ) return [ false, null, 'bits-range' ];

        return [ true, $payload, null ];
    }

    // ── pass cookie ───────────────────────────────────────────────────────────

    /**
     * Validate the abp pass cookie value.
     * Returns [bool $valid, ?string $error].
     */
    public static function validate_pass_cookie( string $val ): array {
        if ( ! str_starts_with( $val, 'v2.' ) ) return [ false, 'bad-prefix' ];

        $rest  = substr( $val, 3 );
        $parts = explode( '.', $rest );
        if ( count( $parts ) !== 2 ) return [ false, 'bad-format' ];

        [ $p64, $sig ] = $parts;
        $json = self::b64url_dec( $p64 );
        if ( $json === '' ) return [ false, 'bad-payload' ];

        $payload = json_decode( $json, true );
        if ( ! is_array( $payload ) || (int) ( $payload['v'] ?? 0 ) !== 2 ) return [ false, 'bad-v' ];

        $kid  = (string) ( $payload['kid'] ?? '' );
        $keys = self::pow_keys();
        if ( ! $keys ) return [ false, 'no-secret' ];

        $candidates = [];
        if ( $kid !== '' && isset( $keys[ $kid ] ) ) $candidates[] = $keys[ $kid ];
        foreach ( $keys as $k ) $candidates[] = $k;
        $candidates = array_values( array_unique( $candidates ) );

        $ok_sig = false;
        foreach ( $candidates as $k ) {
            if ( hash_equals( self::hmac_b64( $p64, $k ), $sig ) ) { $ok_sig = true; break; }
        }
        if ( ! $ok_sig ) return [ false, 'sig' ];

        $now = time();
        $exp = (int) ( $payload['exp'] ?? 0 );
        $iat = (int) ( $payload['iat'] ?? 0 );
        if ( $exp < $now || $iat > ( $now + 60 ) ) return [ false, 'expired' ];

        $uah = (string) ( $payload['uah'] ?? '' );
        if ( $uah === '' || ! hash_equals( $uah, self::ua_hash_b64() ) ) return [ false, 'ua-mismatch' ];

        return [ true, null ];
    }

    /**
     * Issue a signed pass cookie value string (does NOT call setcookie).
     */
    public static function issue_pass_cookie( string $kid, string $key, int $cookie_ttl ): string {
        $iat = time();
        $exp = $iat + $cookie_ttl;

        $payload = [
            'v'   => 2,
            'kid' => $kid,
            'iat' => $iat,
            'exp' => $exp,
            'uah' => self::ua_hash_b64(),
            'n'   => self::b64url_enc( random_bytes( 12 ) ),
        ];

        $json = json_encode( $payload, JSON_UNESCAPED_SLASHES );
        if ( ! is_string( $json ) ) throw new \RuntimeException( 'cookie-json-fail' );

        $p64 = self::b64url_enc( $json );
        $sig  = self::hmac_b64( $p64, $key );

        return 'v2.' . $p64 . '.' . $sig;
    }

    // ── PoW math ──────────────────────────────────────────────────────────────

    public static function leading_zero_bits_ok( string $hash_bin, int $bits ): bool {
        $bytes = unpack( 'C*', $hash_bin );
        if ( ! $bytes ) return false;

        $full = intdiv( $bits, 8 );
        $rem  = $bits % 8;

        for ( $i = 1; $i <= $full; $i++ ) {
            if ( ( $bytes[ $i ] ?? 255 ) !== 0 ) return false;
        }
        if ( $rem === 0 ) return true;

        $next = $bytes[ $full + 1 ] ?? 255;
        $mask = ( 0xFF << ( 8 - $rem ) ) & 0xFF;
        return ( ( $next & $mask ) === 0 );
    }
}
