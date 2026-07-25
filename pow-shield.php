<?php
/**
 * Plugin Name: PoW Shield
 * Plugin URI:  https://github.com/AfterPacket/pow-shield-php
 * Description: Lightweight Proof-of-Work (PoW) gateway for WordPress. Reduces abusive traffic without CAPTCHAs or third-party services.
 * Version:     1.0.3
 * Author:      AfterPacket
 * Author URI:  https://github.com/AfterPacket
 * License:     GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: pow-shield
 * Requires at least: 5.9
 * Requires PHP: 8.0
 */

declare(strict_types=1);

if (!defined("ABSPATH")) {
    exit();
}

define("POW_SHIELD_VERSION", "1.0.3");
define("POW_SHIELD_DIR", plugin_dir_path(__FILE__));
define("POW_SHIELD_URL", plugin_dir_url(__FILE__));

require_once POW_SHIELD_DIR . "includes/class-pow-tier.php";
require_once POW_SHIELD_DIR . "includes/class-pow-verify.php";
require_once POW_SHIELD_DIR . "includes/class-pow-challenge.php";
require_once POW_SHIELD_DIR . "includes/class-pow-admin.php";
require_once POW_SHIELD_DIR . "includes/class-pow-core.php";

add_action("plugins_loaded", ["Pow_Shield_Core", "init"], 1);
add_action("plugins_loaded", ["Pow_Shield_Admin", "init"], 5);

register_activation_hook(__FILE__, "pow_shield_activate");
register_deactivation_hook(__FILE__, "pow_shield_deactivate");

function pow_shield_activate(): void
{
    if (!get_option("pow_shield_secret")) {
        update_option("pow_shield_secret", bin2hex(random_bytes(32)), false);
    }
    if (false === get_option("pow_shield_options")) {
        update_option(
            "pow_shield_options",
            [
                "enabled" => true,
                "protect_login" => true,
                "cookie_ttl" => 21600,
                "bits_desktop" => 20,
                "bits_mobile" => 18,
                "bits_privacy" => 16,
                "exclude_paths" => [],
            ],
            false,
        );
    }
}

function pow_shield_deactivate(): void
{
    // intentionally blank
}
