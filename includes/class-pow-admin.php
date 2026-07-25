<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * WordPress admin settings page for PoW Shield.
 */
class Pow_Shield_Admin {

    public static function init(): void {
        if ( ! is_admin() ) return;

        add_action( 'admin_menu',                                         [ __CLASS__, 'add_menu'            ] );
        add_action( 'admin_init',                                         [ __CLASS__, 'register_settings'   ] );
        add_action( 'admin_post_pow_shield_regenerate_secret',            [ __CLASS__, 'regenerate_secret'   ] );
    }

    public static function add_menu(): void {
        add_options_page(
            'PoW Shield Settings',
            'PoW Shield',
            'manage_options',
            'pow-shield',
            [ __CLASS__, 'render_settings_page' ]
        );
    }

    public static function register_settings(): void {
        register_setting( 'pow_shield_settings_group', 'pow_shield_options', [
            'sanitize_callback' => [ __CLASS__, 'sanitize_options' ],
        ] );
    }

    public static function sanitize_options( mixed $input ): array {
        if ( ! is_array( $input ) ) $input = [];

        $raw_paths = (string) ( $input['exclude_paths'] ?? '' );
        $paths     = array_values( array_filter( array_map( 'sanitize_text_field', explode( "\n", $raw_paths ) ) ) );

        return [
            'enabled'       => ! empty( $input['enabled'] ),
            'protect_login' => ! empty( $input['protect_login'] ),
            'cookie_ttl'    => max( 300,  min( 86400, (int) ( $input['cookie_ttl']   ?? 21600 ) ) ),
            'bits_desktop'  => max( 16,   min( 24,    (int) ( $input['bits_desktop'] ?? 20    ) ) ),
            'bits_mobile'   => max( 14,   min( 22,    (int) ( $input['bits_mobile']  ?? 18    ) ) ),
            'bits_privacy'  => max( 12,   min( 20,    (int) ( $input['bits_privacy'] ?? 16    ) ) ),
            'exclude_paths' => $paths,
        ];
    }

    public static function regenerate_secret(): void {
        check_admin_referer( 'pow_shield_regenerate_secret' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

        $current = (string) get_option( 'pow_shield_secret', '' );
        if ( $current !== '' ) {
            update_option( 'pow_shield_secret_prev', $current, false );
        }
        update_option( 'pow_shield_secret', bin2hex( random_bytes( 32 ) ), false );

        wp_safe_redirect( admin_url( 'options-general.php?page=pow-shield&rotated=1' ) );
        exit;
    }

    public static function render_settings_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;

        $opts = array_merge( [
            'enabled'       => true,
            'protect_login' => true,
            'cookie_ttl'    => 21600,
            'bits_desktop'  => 20,
            'bits_mobile'   => 18,
            'bits_privacy'  => 16,
            'exclude_paths' => [],
        ], (array) get_option( 'pow_shield_options', [] ) );

        $secret         = (string) get_option( 'pow_shield_secret', '' );
        $secret_defined = defined( 'POW_SHIELD_SECRET' );
        $rotated        = isset( $_GET['rotated'] );

        $secret_preview = $secret !== ''
            ? ( substr( $secret, 0, 8 ) . str_repeat( '*', max( 0, strlen( $secret ) - 8 ) ) . ' (' . strlen( $secret ) . ' chars)' )
            : '(none — plugin not activated yet?)';
        ?>
        <div class="wrap">
          <h1>&#x26A1; PoW Shield</h1>
          <p>A lightweight Proof-of-Work gateway for WordPress. Blocks bots and scrapers without CAPTCHAs.</p>

          <?php if ( $rotated ) : ?>
            <div class="notice notice-success is-dismissible"><p><strong>Secret rotated.</strong> Old cookies will expire naturally; new visitors will re-verify.</p></div>
          <?php endif; ?>

          <form method="post" action="options.php">
            <?php settings_fields( 'pow_shield_settings_group' ); ?>

            <h2>General</h2>
            <table class="form-table" role="presentation">
              <tr>
                <th scope="row">Enable PoW Shield</th>
                <td>
                  <label>
                    <input type="checkbox" name="pow_shield_options[enabled]" value="1"
                      <?php checked( ! empty( $opts['enabled'] ) ); ?>>
                    Gate all front-end GET/HEAD requests with a proof-of-work challenge
                  </label>
                </td>
              </tr>
              <tr>
                <th scope="row">Protect wp-login.php</th>
                <td>
                  <label>
                    <input type="checkbox" name="pow_shield_options[protect_login]" value="1"
                      <?php checked( ! empty( $opts['protect_login'] ) ); ?>>
                    Require a solved PoW pass cookie before wp-login.php (GET and POST) is served
                  </label>
                  <p class="description">Recommended — stops credential-stuffing/brute-force bots that hit wp-login.php directly. Does not affect the WordPress session/auth cookies or how you log in; it only gates the request before WordPress sees it. Disable this if you have an external system that POSTs to wp-login.php directly without first loading it in a browser.</p>
                </td>
              </tr>
              <tr>
                <th scope="row"><label for="ps_cookie_ttl">Cookie TTL</label></th>
                <td>
                  <input type="number" id="ps_cookie_ttl" name="pow_shield_options[cookie_ttl]"
                    value="<?php echo esc_attr( (string) $opts['cookie_ttl'] ); ?>"
                    min="300" max="86400" class="small-text"> seconds
                  <p class="description">How long the pass cookie is valid (300 – 86400 s). Default: 21600 (6 hours).</p>
                </td>
              </tr>
            </table>

            <h2>Difficulty (bits of leading zeros)</h2>
            <p class="description">Higher = more work for the visitor's browser. Tier system auto-adjusts based on risk score.</p>
            <table class="form-table" role="presentation">
              <tr>
                <th scope="row"><label for="ps_bits_d">Desktop</label></th>
                <td><input type="number" id="ps_bits_d" name="pow_shield_options[bits_desktop]"
                  value="<?php echo esc_attr( (string) $opts['bits_desktop'] ); ?>" min="16" max="24" class="small-text"></td>
              </tr>
              <tr>
                <th scope="row"><label for="ps_bits_m">Mobile UA</label></th>
                <td><input type="number" id="ps_bits_m" name="pow_shield_options[bits_mobile]"
                  value="<?php echo esc_attr( (string) $opts['bits_mobile'] ); ?>" min="14" max="22" class="small-text"></td>
              </tr>
              <tr>
                <th scope="row"><label for="ps_bits_p">Privacy browsers (LibreWolf, etc.)</label></th>
                <td><input type="number" id="ps_bits_p" name="pow_shield_options[bits_privacy]"
                  value="<?php echo esc_attr( (string) $opts['bits_privacy'] ); ?>" min="12" max="20" class="small-text"></td>
              </tr>
            </table>

            <h2>Excluded Paths</h2>
            <table class="form-table" role="presentation">
              <tr>
                <th scope="row"><label for="ps_excludes">Skip paths</label></th>
                <td>
                  <textarea id="ps_excludes" name="pow_shield_options[exclude_paths]"
                    rows="6" cols="50" class="large-text code"
                  ><?php echo esc_textarea( implode( "\n", (array) $opts['exclude_paths'] ) ); ?></textarea>
                  <p class="description">One path fragment per line. Requests whose URI contains a listed string skip the PoW check.<br>
                  <code>/wp-admin/</code>, REST API, cron, and XML-RPC are always skipped automatically. <code>/wp-login.php</code> is gated by default — see "Protect wp-login.php" above.</p>
                </td>
              </tr>
            </table>

            <?php submit_button( 'Save Settings' ); ?>
          </form>

          <hr>
          <h2>Secret Management</h2>
          <?php if ( $secret_defined ) : ?>
            <p>
              <strong><code>POW_SHIELD_SECRET</code></strong> is defined in <code>wp-config.php</code>.
              Remove or update it there. The database option is ignored while the constant exists.
            </p>
          <?php else : ?>
            <p>Current secret: <code><?php echo esc_html( $secret_preview ); ?></code></p>
            <p>To define it in <code>wp-config.php</code> instead (recommended for production):</p>
            <pre style="background:#f6f7f7;padding:10px;border-radius:4px;overflow:auto">define( 'POW_SHIELD_SECRET', 'your-64-char-random-string-here' );</pre>

            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
              <input type="hidden" name="action" value="pow_shield_regenerate_secret">
              <?php wp_nonce_field( 'pow_shield_regenerate_secret' ); ?>
              <p>
                <button type="submit" class="button button-secondary"
                  onclick="return confirm('Rotate the secret? Existing valid cookies will still work until they expire (previous secret is kept for one rotation cycle).')">
                  &#x1F504; Rotate Secret
                </button>
              </p>
            </form>
          <?php endif; ?>

          <hr>
          <h2>How It Works</h2>
          <ol>
            <li>Every new visitor's browser is asked to compute a SHA-256 hash with enough leading zero bits.</li>
            <li>Once solved, the server issues a signed <code>abp</code> cookie (valid for the configured TTL).</li>
            <li>Subsequent requests from that browser carry the cookie and pass through instantly.</li>
            <li>The adaptive tier system increases difficulty for IPs showing bot-like behaviour.</li>
          </ol>
          <p><a href="https://github.com/AfterPacket/pow-shield-php" target="_blank" rel="noopener">GitHub &rarr; AfterPacket/pow-shield-php</a></p>
        </div>
        <?php
    }
}
