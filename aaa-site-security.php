<?php
/**
 * Plugin Name: AAA Site Security
 * Description: Complete site hardening in one file — CAPTCHA, login lockout, email verification, user-creation lockdown, privilege-escalation guard, REST/XML-RPC control, author-enumeration blocking, security headers, optional secret login URL, and a core/uploads integrity scanner.
 * Version:     2.6.1
 * Author:      Site owner
 *
 * INSTALL
 *   1. Upload to  wp-content/plugins/aaa-site-security.php
 *   2. Activate under Plugins.
 *   3. DELETE the old hardening block from the theme's functions.php.
 *      Leaving both active will cause fatal "cannot redeclare function" errors.
 *
 *   The "aaa-" prefix is deliberate: WordPress loads active plugins in
 *   alphabetical order, so this runs before every other plugin.
 *
 * IF YOU LOCK YOURSELF OUT
 *   Rename or delete this file in the File Manager. That is the recovery route,
 *   and it needs real file access — deactivating from wp-admin is blocked.
 *
 * WHAT CHANGED vs THE functions.php VERSION
 *   - WooCommerce hooks now register on plugins_loaded. A plugin loads before
 *     WooCommerce, so the old top-level class_exists() test would always fail.
 *   - The secret-login-slug handler now runs on plugins_loaded rather than at
 *     file load, which is where wp-login.php can safely be handed control.
 *   - The REST gate matches the ROUTE, not the request URI. The old version
 *     matched the whole URI, so ANY route became anonymous by appending
 *     ?x=contact-form-7.
 *   - BYPASS_CAPTCHA now disables only the CAPTCHA, not the whole file.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/* =========================================================================
 * CONFIG — everything is edited here. wp-config.php values take precedence.
 * ====================================================================== */

/* --- Module switches -------------------------------------------------- */
if ( ! defined( 'BLZ_ENABLE_CAPTCHA' ) )              define( 'BLZ_ENABLE_CAPTCHA', true );
if ( ! defined( 'BLZ_REQUIRE_EMAIL_VERIFICATION' ) )  define( 'BLZ_REQUIRE_EMAIL_VERIFICATION', true );
if ( ! defined( 'BLZ_SECURITY_SCAN' ) )               define( 'BLZ_SECURITY_SCAN', true );
if ( ! defined( 'BLZ_CORE_SCAN' ) )                   define( 'BLZ_CORE_SCAN', true );
if ( ! defined( 'BLZ_UPLOADS_SCAN' ) )                define( 'BLZ_UPLOADS_SCAN', true );

/* --- Login protection ------------------------------------------------- */
if ( ! defined( 'BLZ_MAX_LOGIN_ATTEMPTS' ) )          define( 'BLZ_MAX_LOGIN_ATTEMPTS', 5 );
if ( ! defined( 'BLZ_LOCKOUT_SECONDS' ) )             define( 'BLZ_LOCKOUT_SECONDS', HOUR_IN_SECONDS );
if ( ! defined( 'BLZ_CAPTCHA_TTL' ) )                 define( 'BLZ_CAPTCHA_TTL', 5 * MINUTE_IN_SECONDS );
if ( ! defined( 'BLZ_MIN_FORM_SECONDS' ) )            define( 'BLZ_MIN_FORM_SECONDS', 2 );
if ( ! defined( 'BLZ_CHECKOUT_CAPTCHA_ALWAYS' ) )     define( 'BLZ_CHECKOUT_CAPTCHA_ALWAYS', false );

/* --- User lockdown ---------------------------------------------------- */
// Set true to let the public register again (still forced to a safe role).
if ( ! defined( 'BLZ_ALLOW_CUSTOMER_REGISTRATION' ) ) define( 'BLZ_ALLOW_CUSTOMER_REGISTRATION', false );
// Role forced on public signups. Empty = customer if WooCommerce is active.
if ( ! defined( 'BLZ_PUBLIC_ROLE' ) )                 define( 'BLZ_PUBLIC_ROLE', '' );
// Roles allowed to keep administrator-level capabilities.
// Add 'shop_manager' here if you use WooCommerce shop managers.
if ( ! defined( 'BLZ_ROLE_CAP_EXEMPT' ) )             define( 'BLZ_ROLE_CAP_EXEMPT', array( 'administrator' ) );
// Strip admin-level caps from non-admin roles at READ time. Off by default:
// a plugin that re-registers its roles will see the stripped capability
// missing and re-add it on every request, fighting this filter forever.
// map_meta_cap in section 12 already denies those capabilities regardless,
// so this is belt-and-braces you probably do not need.
if ( ! defined( 'BLZ_LOCK_ROLE_CAPS' ) )              define( 'BLZ_LOCK_ROLE_CAPS', false );
// Panic switch: true allows ALL user writes again (troubleshooting only).
if ( ! defined( 'BLZ_ALLOW_USER_WRITE' ) )            define( 'BLZ_ALLOW_USER_WRITE', false );

/* --- REST API --------------------------------------------------------- */
// Routes anonymous visitors may reach. Matched against the ROUTE, not the URL,
// so no query string can fake a match.
if ( ! defined( 'BLZ_PUBLIC_REST_ROUTES' ) ) define( 'BLZ_PUBLIC_REST_ROUTES', array(
	'/wc/store/',        // WooCommerce Store API: block cart, checkout, products
	'/contact-form-7/',  // remove if you do not use Contact Form 7
) );
// Denied even if a prefix above would allow them.
if ( ! defined( 'BLZ_REST_DENY_ROUTES' ) ) define( 'BLZ_REST_DENY_ROUTES', array(
	// '/wc/store/v1/products/reviews',
) );

/* --- Misc ------------------------------------------------------------- */
if ( ! defined( 'BLZ_SHOW_AUTHOR' ) )                 define( 'BLZ_SHOW_AUTHOR', false );
if ( ! defined( 'BLZ_ENABLE_HSTS' ) )                 define( 'BLZ_ENABLE_HSTS', false );
if ( ! defined( 'BLZ_TRUST_PROXY' ) )                 define( 'BLZ_TRUST_PROXY', false );
if ( ! defined( 'BLZ_ALERT_EMAIL' ) )                 define( 'BLZ_ALERT_EMAIL', '' );

// Alerting. 'digest' (default) = one email a day, and only on a day that had
// something real; critical events still go out at once. 'immediate' = email
// every notice-or-worse event as it happens. 'off' = never email anything.
//
// 'off' disables EMAIL ONLY. Every block, guard, scan and lockout still runs,
// and events are still recorded — check Tools -> User Audit instead.
if ( ! defined( 'BLZ_ALERT_MODE' ) )                  define( 'BLZ_ALERT_MODE', 'digest' );
// Set false to hold even critical events until the daily digest.
if ( ! defined( 'BLZ_CRITICAL_IMMEDIATE' ) )          define( 'BLZ_CRITICAL_IMMEDIATE', true );
// Hour of day (site time, 0-23) the digest is sent.
if ( ! defined( 'BLZ_DIGEST_HOUR' ) )                 define( 'BLZ_DIGEST_HOUR', 7 );
// Events older than this are deleted nightly from {prefix}blz_events.
if ( ! defined( 'BLZ_LOG_RETENTION_DAYS' ) )          define( 'BLZ_LOG_RETENTION_DAYS', 10 );
// Bump only when the table schema changes.
define( 'BLZ_DB_VERSION', 1 );
if ( ! defined( 'BLZ_UPLOADS_QUARANTINE_DAYS' ) )     define( 'BLZ_UPLOADS_QUARANTINE_DAYS', 30 );
// Secret login URL, e.g. 'my-secret-login'. Empty = wp-login.php works normally.
if ( ! defined( 'BLZ_LOGIN_SLUG' ) )                  define( 'BLZ_LOGIN_SLUG', '' );

// IPs never locked out. Put your own office/home IP here before going live —
// if this site sits behind a proxy and BLZ_TRUST_PROXY is wrong, every visitor
// shares one IP and five failures locks out the entire world.
if ( ! defined( 'BLZ_LOGIN_IP_ALLOWLIST' ) )          define( 'BLZ_LOGIN_IP_ALLOWLIST', array() );

// Refuse uploads with an executable extension, and drop a deny-PHP .htaccess
// into /uploads/ so anything already dropped there cannot be executed.
if ( ! defined( 'BLZ_BLOCK_PHP_UPLOADS' ) )           define( 'BLZ_BLOCK_PHP_UPLOADS', true );
if ( ! defined( 'BLZ_HARDEN_UPLOADS_DIR' ) )          define( 'BLZ_HARDEN_UPLOADS_DIR', true );

/* =========================================================================
 * 1. SHARED HELPERS
 * ====================================================================== */

/**
 * HTTP_X_FORWARDED_FOR is client-spoofable. It is trusted only when
 * BLZ_TRUST_PROXY is true (set that only behind a known proxy/CDN).
 */
function blz_get_secure_user_ip() {
	$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

	if ( BLZ_TRUST_PROXY && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$ip = trim( strtok( $_SERVER['HTTP_X_FORWARDED_FOR'], ',' ) );
	}

	$clean = filter_var( $ip, FILTER_VALIDATE_IP );
	return $clean ?: '0.0.0.0';
}

// Backwards-compatible alias for anything that referenced the old name.
if ( ! function_exists( 'get_secure_user_ip' ) ) {
	function get_secure_user_ip() {
		return blz_get_secure_user_ip();
	}
}

function blz_login_key() {
	return 'blz_login_fail_' . md5( blz_get_secure_user_ip() );
}

/**
 * Should this IP be exempt from the lockout counter?
 * A bogus IP (proxy misconfiguration) would otherwise let one bot lock out
 * every visitor at once, because they would all share the same counter.
 */
function blz_login_lockout_exempt() {
	$ip = blz_get_secure_user_ip();
	if ( '0.0.0.0' === $ip ) {
		return true;
	}
	$allow = is_array( BLZ_LOGIN_IP_ALLOWLIST ) ? BLZ_LOGIN_IP_ALLOWLIST : array();
	return in_array( $ip, $allow, true );
}

function blz_captcha_enabled() {
	if ( defined( 'BYPASS_CAPTCHA' ) && BYPASS_CAPTCHA ) {
		return false; // safety valve, scoped to the CAPTCHA only
	}
	return (bool) BLZ_ENABLE_CAPTCHA;
}

function blz_alert_recipient() {
	return BLZ_ALERT_EMAIL ? BLZ_ALERT_EMAIL : get_option( 'admin_email' );
}

/* =========================================================================
 * 2. STRICT LOGIN BLOCKING (the wall) — runs before the login page loads
 * ====================================================================== */

add_action( 'login_init', function () {
	if ( blz_login_lockout_exempt() ) {
		return;
	}
	if ( (int) get_transient( blz_login_key() ) >= BLZ_MAX_LOGIN_ATTEMPTS ) {
		wp_die(
			'Too many failed login attempts. Your IP (' . esc_html( blz_get_secure_user_ip() ) . ') is temporarily locked.',
			'Access Denied',
			array( 'response' => 403 )
		);
	}
} );

/* =========================================================================
 * 3. IMAGE CAPTCHA
 * The answer lives in a transient server-side and never appears in the HTML,
 * so it cannot be scraped. One-time use per token. Falls back to a math
 * question if the GD extension is unavailable.
 * ====================================================================== */

/**
 * @return array{token:string, code:string, image:string|false}
 */
function blz_create_captcha() {
	$token = wp_generate_password( 20, false );

	if ( function_exists( 'imagecreatetruecolor' ) ) {
		$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // ambiguous characters removed
		$code  = '';
		for ( $i = 0; $i < 5; $i++ ) {
			$code .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}
		$image = blz_render_captcha_image( $code );
	} else {
		$n1    = random_int( 1, 9 );
		$n2    = random_int( 1, 9 );
		$code  = (string) ( $n1 + $n2 );
		$image = false; // signals text mode
		set_transient( 'blz_cap_q_' . $token, "$n1 + $n2", BLZ_CAPTCHA_TTL );
	}

	set_transient( 'blz_cap_' . $token, array(
		'code' => strtolower( $code ),
		'time' => time(),
	), BLZ_CAPTCHA_TTL );

	return array( 'token' => $token, 'code' => $code, 'image' => $image );
}

/** Distorted CAPTCHA image returned as an inline data URI (no extra request). */
function blz_render_captcha_image( $code ) {
	$w   = 150;
	$h   = 50;
	$img = imagecreatetruecolor( $w, $h );

	$bg = imagecolorallocate( $img, 245, 245, 245 );
	imagefilledrectangle( $img, 0, 0, $w, $h, $bg );

	for ( $i = 0; $i < 500; $i++ ) {
		$noise = imagecolorallocate( $img, random_int( 180, 230 ), random_int( 180, 230 ), random_int( 180, 230 ) );
		imagesetpixel( $img, random_int( 0, $w ), random_int( 0, $h ), $noise );
	}

	for ( $i = 0; $i < 5; $i++ ) {
		$line = imagecolorallocate( $img, random_int( 120, 180 ), random_int( 120, 180 ), random_int( 120, 180 ) );
		imageline( $img, random_int( 0, $w ), random_int( 0, $h ), random_int( 0, $w ), random_int( 0, $h ), $line );
	}

	$len = strlen( $code );
	$x   = 15;
	for ( $i = 0; $i < $len; $i++ ) {
		$fg = imagecolorallocate( $img, random_int( 0, 90 ), random_int( 0, 90 ), random_int( 0, 90 ) );
		$y  = random_int( 12, 22 );
		imagestring( $img, 5, $x, $y, $code[ $i ], $fg );
		$x += 25;
	}

	ob_start();
	imagepng( $img );
	$data = ob_get_clean();
	imagedestroy( $img );

	return 'data:image/png;base64,' . base64_encode( $data );
}

/**
 * CAPTCHA + honeypot + timing token fields.
 * On WooCommerce forms the markup mirrors WooCommerce's own field structure so
 * the active theme styles it like the surrounding fields.
 */
function blz_output_captcha_fields( $context = 'login' ) {
	if ( ! blz_captcha_enabled() ) {
		return;
	}

	$captcha = blz_create_captcha();
	$wc      = ( 'woocommerce' === $context );

	$input_class = $wc ? 'woocommerce-Input woocommerce-Input--text input-text' : 'input';
	$input_style = $wc ? '' : ' style="width:100%;max-width:280px;"';

	echo $wc
		? '<p class="form-row form-row-wide blz-captcha">'
		: '<div class="blz-captcha" style="margin-bottom:16px;">';

	echo $wc
		? '<label>Security check&nbsp;<span class="required">*</span></label>'
		: '<label style="display:block;margin-bottom:6px;">Security check</label>';

	if ( $captcha['image'] ) {
		echo '<img src="' . esc_attr( $captcha['image'] ) . '" alt="CAPTCHA" style="display:block;margin-bottom:8px;border:1px solid #ccc;" />';
		echo '<input type="text" name="blz_captcha" class="' . esc_attr( $input_class ) . '" required autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Enter the code above"' . $input_style . ' />';
	} else {
		$q = get_transient( 'blz_cap_q_' . $captcha['token'] );
		echo '<span class="blz-captcha-q">' . esc_html( $q ) . ' = ?</span><br />';
		echo '<input type="number" name="blz_captcha" class="' . esc_attr( $input_class ) . '" required autocomplete="off"' . $input_style . ' />';
	}

	echo '<input type="hidden" name="blz_captcha_token" value="' . esc_attr( $captcha['token'] ) . '" />';

	// Honeypot: hidden from humans, tempting to bots. Must stay empty.
	echo '<input type="text" name="blz_hp_url" value="" autocomplete="off" tabindex="-1" aria-hidden="true" style="position:absolute;left:-9999px;top:-9999px;" />';

	echo $wc ? '</p>' : '</div>';
}

function blz_output_captcha_fields_wc() {
	blz_output_captcha_fields( 'woocommerce' );
}

add_action( 'login_form', 'blz_output_captcha_fields' );
add_action( 'register_form', 'blz_output_captcha_fields' );
add_action( 'lostpassword_form', 'blz_output_captcha_fields' );

/* =========================================================================
 * 4. VALIDATE CAPTCHA / HONEYPOT / TIMING
 * ====================================================================== */

/**
 * Consumes the token (one-time use) regardless of outcome, so it cannot be
 * replayed. Returns true on success, WP_Error on failure.
 */
function blz_validate_captcha_post() {
	if ( ! blz_captcha_enabled() ) {
		return true;
	}

	if ( ! empty( $_POST['blz_hp_url'] ) ) {
		return new WP_Error( 'blz_bot', '<strong>ERROR</strong>: Request rejected.' );
	}

	$token  = isset( $_POST['blz_captcha_token'] ) ? sanitize_text_field( wp_unslash( $_POST['blz_captcha_token'] ) ) : '';
	$answer = isset( $_POST['blz_captcha'] ) ? strtolower( trim( sanitize_text_field( wp_unslash( $_POST['blz_captcha'] ) ) ) ) : '';

	if ( '' === $token || '' === $answer ) {
		return new WP_Error( 'blz_captcha_missing', '<strong>ERROR</strong>: Security check missing.' );
	}

	$stored = get_transient( 'blz_cap_' . $token );
	delete_transient( 'blz_cap_' . $token );
	delete_transient( 'blz_cap_q_' . $token );

	if ( ! is_array( $stored ) ) {
		return new WP_Error( 'blz_captcha_expired', '<strong>ERROR</strong>: Security check expired. Please try again.' );
	}

	if ( ( time() - (int) $stored['time'] ) < BLZ_MIN_FORM_SECONDS ) {
		return new WP_Error( 'blz_too_fast', '<strong>ERROR</strong>: Request rejected.' );
	}

	if ( ! hash_equals( (string) $stored['code'], $answer ) ) {
		return new WP_Error( 'blz_captcha_wrong', '<strong>ERROR</strong>: Incorrect security code.' );
	}

	return true;
}

// Covers wp-login.php AND WooCommerce logins — every credential login funnels
// through wp_authenticate_user.
add_filter( 'wp_authenticate_user', function ( $user, $password ) {
	if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) {
		return $user;
	}

	// Lockout wall for login forms that never hit login_init (WooCommerce My
	// Account posts to its own page).
	if ( ! blz_login_lockout_exempt() && (int) get_transient( blz_login_key() ) >= BLZ_MAX_LOGIN_ATTEMPTS ) {
		return new WP_Error( 'blz_locked', '<strong>ERROR</strong>: Too many failed attempts. Please try again later.' );
	}

	$check = blz_validate_captcha_post();
	if ( is_wp_error( $check ) ) {
		do_action( 'wp_login_failed', $check->get_error_code() );
		return $check;
	}

	return $user;
}, 10, 2 );

add_filter( 'registration_errors', function ( $errors ) {
	$check = blz_validate_captcha_post();
	if ( is_wp_error( $check ) ) {
		$errors->add( $check->get_error_code(), $check->get_error_message() );
	}
	return $errors;
} );

// wp-login.php?action=lostpassword and WooCommerce's lost-password form both
// funnel through this action.
add_action( 'lostpassword_post', function ( $errors ) {
	if ( is_admin() && ! wp_doing_ajax() ) {
		return; // admin-triggered reset from the Users screen has no CAPTCHA form
	}
	$check = blz_validate_captcha_post();
	if ( is_wp_error( $check ) && is_wp_error( $errors ) ) {
		$errors->add( $check->get_error_code(), $check->get_error_message() );
	}
} );

/* =========================================================================
 * 5. WOOCOMMERCE INTEGRATION
 *
 * Registered on plugins_loaded: this plugin loads BEFORE WooCommerce, so a
 * top-level class_exists() test would always be false.
 *
 * Checkout CAPTCHA: guests only by default — logged-in customers already
 * passed one to log in. Set BLZ_CHECKOUT_CAPTCHA_ALWAYS to challenge everyone.
 *
 * NOTE: these are CLASSIC (shortcode) checkout hooks. If you use the BLOCK
 * cart/checkout, the Store API never fires them, so the CAPTCHA silently does
 * not appear there. Nothing breaks; there is simply no challenge.
 * ====================================================================== */

function blz_checkout_captcha_required() {
	if ( BLZ_CHECKOUT_CAPTCHA_ALWAYS ) {
		return true;
	}
	return ! is_user_logged_in();
}

add_action( 'plugins_loaded', function () {

	if ( ! class_exists( 'WooCommerce' ) ) {
		return;
	}

	// My Account login form (also shown on the checkout page). Submissions are
	// validated by the wp_authenticate_user filter above.
	add_action( 'woocommerce_login_form', 'blz_output_captcha_fields_wc' );

	// Lost-password form (validated by the shared lostpassword_post hook).
	add_action( 'woocommerce_lostpassword_form', 'blz_output_captcha_fields_wc' );

	// Registration form.
	add_action( 'woocommerce_register_form', 'blz_output_captcha_fields_wc' );
	add_filter( 'woocommerce_registration_errors', function ( $errors ) {
		// Account creation during checkout is covered by the checkout
		// validation below; the token is one-time use, so don't check twice.
		if ( defined( 'WOOCOMMERCE_CHECKOUT' ) && WOOCOMMERCE_CHECKOUT ) {
			return $errors;
		}
		$check = blz_validate_captcha_post();
		if ( is_wp_error( $check ) ) {
			$errors->add( $check->get_error_code(), $check->get_error_message() );
		}
		return $errors;
	} );

	// Render with the customer details, not inside the order-review block —
	// WooCommerce re-renders that via AJAX on every address change, which would
	// wipe the customer's answer.
	add_action( 'woocommerce_after_order_notes', function () {
		if ( blz_checkout_captcha_required() ) {
			blz_output_captcha_fields_wc();
		}
	} );

	add_action( 'woocommerce_after_checkout_validation', function ( $data, $errors ) {
		if ( ! blz_checkout_captcha_required() ) {
			return;
		}
		$check = blz_validate_captcha_post();
		if ( is_wp_error( $check ) ) {
			$errors->add( $check->get_error_code(), wp_strip_all_tags( $check->get_error_message() ) );
		}
	}, 10, 2 );

	// Don't auto-login newly registered customers who still need to verify.
	add_filter( 'woocommerce_registration_auth_new_customer', function ( $auth, $customer_id ) {
		if ( blz_email_verification_enabled() && get_user_meta( $customer_id, 'blz_email_verify_key', true ) ) {
			if ( function_exists( 'wc_add_notice' ) ) {
				wc_add_notice( 'Account created — please check your email and click the verification link before logging in.', 'notice' );
			}
			return false;
		}
		return $auth;
	}, 10, 2 );

	add_action( 'woocommerce_before_customer_login_form', function () {
		if ( isset( $_GET['blz_verified'] ) ) {
			echo '<div class="woocommerce-message">Email verified successfully. You can now log in.</div>';
		}
	} );

	// Checkout submits over AJAX and tokens are one-time use, so after a failed
	// attempt the on-page challenge is spent — swap in a fresh one.
	add_action( 'wp_ajax_blz_refresh_captcha', 'blz_ajax_refresh_captcha' );
	add_action( 'wp_ajax_nopriv_blz_refresh_captcha', 'blz_ajax_refresh_captcha' );
	add_action( 'wp_footer', 'blz_checkout_captcha_js' );

}, 20 );

function blz_ajax_refresh_captcha() {
	// Unauthenticated endpoint: without a limit it is a free transient-writing
	// loop for anyone who wants to fill the options table.
	$key  = 'blz_capref_' . md5( blz_get_secure_user_ip() );
	$hits = (int) get_transient( $key );
	if ( $hits > 30 ) {
		wp_send_json_error( array( 'message' => 'Too many requests.' ), 429 );
	}
	set_transient( $key, $hits + 1, 5 * MINUTE_IN_SECONDS );

	$captcha  = blz_create_captcha();
	$question = '';
	if ( ! $captcha['image'] ) {
		$question = get_transient( 'blz_cap_q_' . $captcha['token'] ) . ' = ?';
	}
	wp_send_json_success( array(
		'token'    => $captcha['token'],
		'image'    => $captcha['image'],
		'question' => $question,
	) );
}

function blz_checkout_captcha_js() {
	if ( ! function_exists( 'is_checkout' ) || ! is_checkout() || is_order_received_page() ) {
		return;
	}
	if ( ! blz_checkout_captcha_required() || ! blz_captcha_enabled() ) {
		return;
	}
	$ajax_url = esc_url( admin_url( 'admin-ajax.php' ) );
	?>
	<script>
	jQuery( function ( $ ) {
		$( document.body ).on( 'checkout_error', function () {
			$.post( '<?php echo $ajax_url; ?>', { action: 'blz_refresh_captcha' }, function ( r ) {
				if ( ! r || ! r.success ) { return; }
				var $box = $( 'form.checkout .blz-captcha' );
				$box.find( 'input[name="blz_captcha_token"]' ).val( r.data.token );
				if ( r.data.image ) {
					$box.find( 'img' ).attr( 'src', r.data.image );
				} else {
					$box.find( '.blz-captcha-q' ).text( r.data.question );
				}
				$box.find( 'input[name="blz_captcha"]' ).val( '' );
			} );
		} );
	} );
	</script>
	<?php
}

/* =========================================================================
 * 6. EMAIL VERIFICATION FOR NEW REGISTRATIONS
 * New front-end registrations get a one-time link and cannot log in until they
 * click it. Exempt: admin-created users, WP-CLI, and accounts created during
 * WooCommerce checkout. Existing users are never affected.
 * ====================================================================== */

function blz_email_verification_enabled() {
	return (bool) BLZ_REQUIRE_EMAIL_VERIFICATION;
}

/**
 * (Re)issue a verification token (hashed at rest) and email the link.
 * Rate-limited to one email per user per 10 minutes unless $force.
 */
function blz_send_verification_email( $user_id, $force = false ) {
	if ( ! $force && get_transient( 'blz_verify_sent_' . $user_id ) ) {
		return;
	}
	$user = get_userdata( $user_id );
	if ( ! $user || ! $user->user_email ) {
		return;
	}

	$token = wp_generate_password( 32, false );
	update_user_meta( $user_id, 'blz_email_verify_key', wp_hash( $token ) );

	$url = add_query_arg(
		array( 'blz_verify' => $user_id, 'blz_key' => rawurlencode( $token ) ),
		home_url( '/' )
	);

	$subject = '[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] Verify your email address';
	$message = 'Hi ' . $user->user_login . ",\n\n"
		. 'Thanks for registering at ' . home_url() . ".\n"
		. "Please confirm your email address by clicking the link below. You will not be able to log in until you do:\n\n"
		. $url . "\n\n"
		. 'If you did not create this account, you can ignore this email.';

	// Transactional, NOT an alert: this must keep working even when
	// BLZ_ALERT_MODE is 'off', because the user cannot log in without it.
	// Wrapped so a broken mail configuration cannot fatal the registration.
	try {
		wp_mail( $user->user_email, $subject, $message );
	} catch ( Throwable $e ) {
		blz_scan_log( 'VERIFICATION MAIL FAILED for user #' . (int) $user_id . ': ' . $e->getMessage() );
	}
	set_transient( 'blz_verify_sent_' . $user_id, 1, 10 * MINUTE_IN_SECONDS );
}

add_action( 'user_register', function ( $user_id ) {
	if ( ! blz_email_verification_enabled() ) {
		return;
	}
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		return;
	}
	if ( is_admin() && current_user_can( 'create_users' ) ) {
		return; // created from wp-admin by a trusted user
	}
	if ( defined( 'WOOCOMMERCE_CHECKOUT' ) && WOOCOMMERCE_CHECKOUT ) {
		return; // created during checkout
	}
	blz_send_verification_email( $user_id, true );
} );

add_action( 'init', function () {
	if ( ! isset( $_GET['blz_verify'], $_GET['blz_key'] ) ) {
		return;
	}
	$uid    = absint( $_GET['blz_verify'] );
	$key    = sanitize_text_field( wp_unslash( $_GET['blz_key'] ) );
	$stored = $uid ? get_user_meta( $uid, 'blz_email_verify_key', true ) : '';

	if ( ! $stored || ! hash_equals( (string) $stored, wp_hash( $key ) ) ) {
		wp_die( 'This verification link is invalid or has already been used.', 'Verification failed', array( 'response' => 400 ) );
	}

	delete_user_meta( $uid, 'blz_email_verify_key' );
	update_user_meta( $uid, 'blz_email_verified', time() );

	$dest = function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'myaccount' ) : wp_login_url();
	wp_safe_redirect( add_query_arg( 'blz_verified', '1', $dest ) );
	exit;
} );

// Priority 30 = after core verifies the password (20), so a wrong password
// never reveals the verification state or triggers a resend.
add_filter( 'authenticate', function ( $user ) {
	if ( ! blz_email_verification_enabled() || ! ( $user instanceof WP_User ) ) {
		return $user;
	}
	if ( ! get_user_meta( $user->ID, 'blz_email_verify_key', true ) ) {
		return $user;
	}
	blz_send_verification_email( $user->ID ); // rate-limited resend
	return new WP_Error(
		'blz_email_unverified',
		'<strong>ERROR</strong>: Please verify your email address before logging in. A verification link has been sent to your inbox (check spam too).'
	);
}, 30 );

add_filter( 'login_message', function ( $message ) {
	if ( isset( $_GET['blz_verified'] ) ) {
		$message .= '<p class="message">Email verified successfully. You can now log in.</p>';
	}
	return $message;
} );

/* =========================================================================
 * 7. FAILURE COUNTER (feeds the lockout wall in section 2)
 * ====================================================================== */

add_action( 'wp_login_failed', function () {
	if ( blz_login_lockout_exempt() ) {
		return;
	}
	$key      = blz_login_key();
	$attempts = (int) get_transient( $key ) + 1;
	set_transient( $key, $attempts, BLZ_LOCKOUT_SECONDS );
} );

add_action( 'wp_login', function () {
	delete_transient( blz_login_key() );
} );

/* =========================================================================
 * 8. USER LOCKDOWN — HELPERS
 * ====================================================================== */

/**
 * True only for a logged-in user who genuinely holds the administrator role.
 * The ROLE is checked, not just the capability: the classic persistence trick
 * is to bolt manage_options onto a subscriber, and a capability-only test
 * would happily accept that attacker.
 */
function blz_actor_is_admin() {
	if ( ! function_exists( 'wp_get_current_user' ) ) {
		return false;
	}
	if ( is_multisite() && function_exists( 'is_super_admin' ) && is_super_admin() ) {
		return true;
	}
	$user = wp_get_current_user();
	if ( empty( $user->ID ) ) {
		return false;
	}
	if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
		return false;
	}
	return user_can( $user, 'create_users' ) && user_can( $user, 'promote_users' );
}

function blz_user_write_authorized() {
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		return true;
	}
	if ( BLZ_ALLOW_USER_WRITE ) {
		return true;
	}
	return blz_actor_is_admin();
}

function blz_public_registration_allowed() {
	return (bool) BLZ_ALLOW_CUSTOMER_REGISTRATION;
}

/** Resolved at call time — WooCommerce is not loaded when this file runs. */
function blz_public_role() {
	if ( BLZ_PUBLIC_ROLE ) {
		return BLZ_PUBLIC_ROLE;
	}
	return class_exists( 'WooCommerce' ) ? 'customer' : 'subscriber';
}

function blz_privileged_roles() {
	$roles = is_array( BLZ_ROLE_CAP_EXEMPT ) ? BLZ_ROLE_CAP_EXEMPT : array( 'administrator' );
	return array_unique( array_merge( array( 'administrator' ), $roles ) );
}

/** Capabilities that mean "this account can own the site". */
function blz_escalation_caps() {
	return array(
		'manage_options', 'edit_users', 'create_users', 'delete_users',
		'promote_users', 'remove_users', 'add_users', 'edit_files',
		'install_plugins', 'edit_plugins', 'delete_plugins', 'activate_plugins',
		'install_themes', 'edit_themes', 'delete_themes', 'switch_themes',
		'update_core', 'update_plugins', 'update_themes',
		'unfiltered_upload', 'manage_network', 'manage_network_users',
	);
}

/** $value is the raw capabilities meta: keys are role names or cap names. */
function blz_caps_are_privileged( $value ) {
	$danger = blz_escalation_caps();
	foreach ( (array) $value as $key => $granted ) {
		if ( empty( $granted ) ) {
			continue;
		}
		if ( in_array( $key, $danger, true ) ) {
			return true;
		}
		if ( in_array( $key, blz_privileged_roles(), true ) ) {
			return true;
		}
		if ( function_exists( 'get_role' ) ) {
			$role = get_role( $key );
			if ( $role ) {
				foreach ( $danger as $cap ) {
					if ( ! empty( $role->capabilities[ $cap ] ) ) {
						return true;
					}
				}
			}
		}
	}
	return false;
}

/* =========================================================================
 * 9. EVENT LOG + ALERTING
 * Critical events email immediately. Everything else accumulates into one
 * digest a day, and no digest is sent on a day with nothing in it.
 * ====================================================================== */
/* --- Design note ----------------------------------------------------------
 * Recording and alerting are SUPPORT systems. Every security control in this
 * file must keep working when they do not:
 *   - no CREATE privilege -> events fall back to a capped option row
 *   - no writable uploads -> the flat log silently no-ops
 *   - BLZ_ALERT_MODE 'off' -> nothing is ever emailed
 *   - broken wp_mail      -> the failure is swallowed, never surfaced
 * blz_sec_event() therefore cannot throw. Its whole body is wrapped, because
 * it is called from inside the guards that block attacks — a logging failure
 * must never become an enforcement failure.
 * ---------------------------------------------------------------------- */

function blz_events_table() {
	global $wpdb;
	return $wpdb->prefix . 'blz_events';
}

/**
 * Create the events table if needed and report whether it is usable.
 * Backs off for 12 hours after a failure: without that, a host with no CREATE
 * privilege would run dbDelta (several queries plus a wp-admin include) on
 * every single page load, forever.
 *
 * @return bool true when the table exists and can be written to.
 */
function blz_maybe_create_tables() {
	static $result = null;

	if ( null !== $result ) {
		return $result;
	}

	global $wpdb;
	$table = blz_events_table();

	if ( (int) get_option( 'blz_db_version', 0 ) >= BLZ_DB_VERSION ) {
		// Confirm once a day that the table is still there — someone may have
		// dropped it, and silently writing into nothing helps no one.
		if ( get_transient( 'blz_table_ok' ) ) {
			$result = true;
			return true;
		}
		$suppress = $wpdb->suppress_errors( true );
		$exists   = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
		$wpdb->suppress_errors( $suppress );

		if ( $exists ) {
			set_transient( 'blz_table_ok', 1, DAY_IN_SECONDS );
			$result = true;
			return true;
		}
		delete_option( 'blz_db_version' ); // gone; fall through and try to rebuild
	}

	if ( get_transient( 'blz_db_retry_block' ) ) {
		$result = false;
		return false;
	}

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$charset = $wpdb->get_charset_collate();

	$sql = "CREATE TABLE {$table} (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		bucket CHAR(32) NOT NULL,
		event_type VARCHAR(60) NOT NULL,
		severity VARCHAR(10) NOT NULL DEFAULT 'notice',
		ip VARCHAR(45) NOT NULL DEFAULT '',
		actor VARCHAR(120) NOT NULL DEFAULT '',
		detail TEXT NULL,
		uri VARCHAR(300) NOT NULL DEFAULT '',
		ua VARCHAR(200) NOT NULL DEFAULT '',
		hits INT UNSIGNED NOT NULL DEFAULT 1,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		notified TINYINT(1) NOT NULL DEFAULT 0,
		PRIMARY KEY  (id),
		UNIQUE KEY bucket (bucket),
		KEY last_seen (last_seen),
		KEY severity (severity),
		KEY notified (notified)
	) {$charset};";

	$suppress = $wpdb->suppress_errors( true );
	@dbDelta( $sql );
	$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	$wpdb->suppress_errors( $suppress );

	if ( ! $exists ) {
		// Verified, not assumed: dbDelta fails quietly without CREATE rights,
		// and recording the version anyway would disable logging permanently.
		set_transient( 'blz_db_retry_block', 1, 12 * HOUR_IN_SECONDS );
		blz_scan_log( 'NOTICE: could not create ' . $table . ' (' . $wpdb->last_error
			. '). Falling back to option storage; all security controls are unaffected.' );
		$result = false;
		return false;
	}

	update_option( 'blz_db_version', BLZ_DB_VERSION, false );
	set_transient( 'blz_table_ok', 1, DAY_IN_SECONDS );

	// Migrate off the old rows only now that the replacement is confirmed.
	delete_option( 'blz_user_events' );
	delete_option( 'blz_digest' );

	$result = true;
	return true;
}

add_action( 'init', 'blz_maybe_create_tables', 1 );

function blz_events_available() {
	return blz_maybe_create_tables();
}

/**
 * Severity decides what reaches the inbox.
 *   critical — someone is actively trying to take the site over. Sent at once.
 *   notice   — worth knowing, but a bot doing this 500 times is still one line
 *              in tomorrow's digest.
 *   info     — background noise. Recorded, never emailed.
 */
function blz_event_severity( $type ) {
	$critical = array(
		'blocked_escalation',        // someone tried to grant admin capabilities
		'blocked_role_edit',         // someone tried to rewrite the role table
		'new_admin_detected',        // an admin appeared by a route the hooks cannot see
		'blocked_self_deactivate',   // someone tried to switch this plugin off
		'backdoor_quarantined',      // executable PHP found inside /uploads/
		'core_files_modified',       // WordPress core does not match the official checksums
		'unknown_core_files',        // unrecognised PHP sitting in wp-admin or wp-includes
		'admin_email_changed',
		'site_admin_email_changed',
	);

	$info = array(
		'blocked_register_page',     // bots hit this constantly; it means nothing
		'role_table_write',          // plugins re-register roles on ordinary requests
		'public_signup',
		'sessions_destroyed',
		'site_admin_email_change_pending',
	);

	if ( in_array( $type, $critical, true ) ) {
		return 'critical';
	}
	if ( in_array( $type, $info, true ) ) {
		return 'info';
	}
	return 'notice';
}

/**
 * Walk the call stack for the first file under wp-content. When something
 * unexpected writes to roles or capabilities, this names the culprit instead
 * of leaving you guessing which plugin it was.
 */
function blz_guilty_file() {
	$frames = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 25 );
	foreach ( $frames as $frame ) {
		if ( empty( $frame['file'] ) ) {
			continue;
		}
		$file = str_replace( '\\', '/', $frame['file'] );
		if ( false === strpos( $file, '/wp-content/' ) ) {
			continue;
		}
		if ( false !== strpos( $file, basename( __FILE__ ) ) ) {
			continue; // skip ourselves
		}
		$rel = substr( $file, strpos( $file, '/wp-content/' ) + 12 );
		return $rel . ':' . (int) ( $frame['line'] ?? 0 );
	}
	return 'unknown';
}

function blz_alerts_enabled() {
	return 'off' !== BLZ_ALERT_MODE;
}

/**
 * Record an event.
 * Never throws, never emits output, never blocks the caller. A failure here is
 * invisible to the security control that called it.
 */
function blz_sec_event( $type, $detail, $notify = true ) {
	try {
		$who = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$ip  = blz_get_secure_user_ip();
		$now = gmdate( 'Y-m-d H:i:s' );

		$entry = array(
			'time'   => time(),
			'type'   => $type,
			'detail' => $detail,
			'ip'     => $ip,
			'user'   => ( $who && $who->ID ) ? $who->user_login . ' (#' . $who->ID . ')' : 'anonymous',
			'uri'    => substr( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), 0, 300 ),
			'ua'     => substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 200 ),
		);

		$severity = $notify ? blz_event_severity( $type ) : 'info';

		// One row per event type + IP + hour. Repeats inside that window just
		// increment the counter, so the daily total stays exact without the
		// row count following it.
		$bucket = md5( $type . '|' . $ip . '|' . gmdate( 'YmdH' ) );

		if ( blz_events_available() ) {
			blz_store_event_row( $bucket, $type, $severity, $entry, $now );
		} else {
			blz_store_event_fallback( $bucket, $type, $severity, $entry );
		}

		// The flat log keeps its own copy: it survives a dropped table and
		// needs no database to read. Throttled so it does not mirror a flood
		// line for line — the counters above already hold the exact total.
		$fingerprint = 'blz_ev_' . md5( $type . '|' . $ip );
		if ( ! get_transient( $fingerprint ) ) {
			set_transient( $fingerprint, 1, MINUTE_IN_SECONDS );
			blz_scan_log( strtoupper( $severity ) . ' ' . strtoupper( $type ) . ': ' . $detail
				. ' | ip=' . $entry['ip'] . ' | actor=' . $entry['user'] . ' | uri=' . $entry['uri'] );
		}

		if ( 'info' === $severity || ! blz_alerts_enabled() ) {
			return;
		}

		if ( 'critical' === $severity && ( BLZ_CRITICAL_IMMEDIATE || 'immediate' === BLZ_ALERT_MODE ) ) {
			blz_send_immediate_alert( $type, $entry );
		} elseif ( 'immediate' === BLZ_ALERT_MODE ) {
			blz_send_immediate_alert( $type, $entry );
		}
	} catch ( Throwable $e ) {
		// Deliberately swallowed. Recording an attack must never break the
		// code that blocked it.
		return;
	}
}

/** Upsert into the events table. Errors suppressed — the caller cannot care. */
function blz_store_event_row( $bucket, $type, $severity, $entry, $now ) {
	global $wpdb;
	$table    = blz_events_table();
	$suppress = $wpdb->suppress_errors( true );

	$wpdb->query( $wpdb->prepare(
		"INSERT INTO {$table}
			(bucket, event_type, severity, ip, actor, detail, uri, ua, hits, first_seen, last_seen, notified)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, 0)
		 ON DUPLICATE KEY UPDATE hits = hits + 1, last_seen = %s, detail = %s",
		$bucket, $type, $severity, $entry['ip'], $entry['user'], $entry['detail'],
		$entry['uri'], $entry['ua'], $now, $now, $now, $entry['detail']
	) );

	$wpdb->suppress_errors( $suppress );
}

/**
 * Degraded storage for hosts with no CREATE privilege: the same hourly
 * buckets, capped at 120 of them, in a single non-autoloaded option.
 */
function blz_store_event_fallback( $bucket, $type, $severity, $entry ) {
	$rows = get_option( 'blz_events_fallback', array() );
	if ( ! is_array( $rows ) ) {
		$rows = array();
	}

	if ( isset( $rows[ $bucket ] ) ) {
		$rows[ $bucket ]['hits']++;
		$rows[ $bucket ]['last'] = $entry['time'];
		$rows[ $bucket ]['detail'] = $entry['detail'];
	} else {
		$rows[ $bucket ] = array(
			'type'     => $type,
			'severity' => $severity,
			'ip'       => $entry['ip'],
			'actor'    => $entry['user'],
			'detail'   => $entry['detail'],
			'uri'      => $entry['uri'],
			'hits'     => 1,
			'first'    => $entry['time'],
			'last'     => $entry['time'],
			'notified' => 0,
		);
	}

	if ( count( $rows ) > 120 ) {
		uasort( $rows, function ( $a, $b ) {
			return $a['last'] <=> $b['last'];
		} );
		$rows = array_slice( $rows, -120, null, true );
	}

	update_option( 'blz_events_fallback', $rows, false );
}

/**
 * Everything waiting for the next digest, from whichever store is in use.
 * @return array of objects with event_type, severity, total, first_seen, last_seen
 */
function blz_collect_pending() {
	global $wpdb;

	if ( blz_events_available() ) {
		$table    = blz_events_table();
		$suppress = $wpdb->suppress_errors( true );
		$rows     = $wpdb->get_results(
			"SELECT event_type, severity, SUM(hits) AS total,
			        MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
			 FROM {$table}
			 WHERE notified = 0 AND severity <> 'info'
			 GROUP BY event_type, severity
			 ORDER BY FIELD(severity,'critical','notice'), total DESC"
		);
		$wpdb->suppress_errors( $suppress );
		return is_array( $rows ) ? $rows : array();
	}

	$grouped = array();
	foreach ( (array) get_option( 'blz_events_fallback', array() ) as $r ) {
		if ( ! empty( $r['notified'] ) || 'info' === $r['severity'] ) {
			continue;
		}
		$key = $r['type'];
		if ( ! isset( $grouped[ $key ] ) ) {
			$grouped[ $key ] = (object) array(
				'event_type' => $r['type'],
				'severity'   => $r['severity'],
				'total'      => 0,
				'first_seen' => gmdate( 'Y-m-d H:i:s', $r['first'] ),
				'last_seen'  => gmdate( 'Y-m-d H:i:s', $r['last'] ),
			);
		}
		$grouped[ $key ]->total += (int) $r['hits'];
		$grouped[ $key ]->last_seen = gmdate( 'Y-m-d H:i:s', max( strtotime( $grouped[ $key ]->last_seen ), $r['last'] ) );
	}
	return array_values( $grouped );
}

/** Flag everything currently pending as sent. */
function blz_mark_notified() {
	global $wpdb;

	if ( blz_events_available() ) {
		$table    = blz_events_table();
		$suppress = $wpdb->suppress_errors( true );
		$wpdb->query( "UPDATE {$table} SET notified = 1 WHERE notified = 0" );
		$wpdb->suppress_errors( $suppress );
		return;
	}

	$rows = get_option( 'blz_events_fallback', array() );
	if ( ! is_array( $rows ) ) {
		return;
	}
	foreach ( $rows as $k => $r ) {
		$rows[ $k ]['notified'] = 1;
	}
	update_option( 'blz_events_fallback', $rows, false );
}

/** Delete events past the retention window, from whichever store is in use. */
function blz_prune_events() {
	$days   = max( 1, (int) BLZ_LOG_RETENTION_DAYS );
	$cutoff = time() - $days * DAY_IN_SECONDS;

	if ( blz_events_available() ) {
		global $wpdb;
		$table    = blz_events_table();
		$suppress = $wpdb->suppress_errors( true );
		$deleted  = $wpdb->query( $wpdb->prepare(
			"DELETE FROM {$table} WHERE last_seen < %s", gmdate( 'Y-m-d H:i:s', $cutoff )
		) );
		$wpdb->suppress_errors( $suppress );
	} else {
		$rows    = (array) get_option( 'blz_events_fallback', array() );
		$before  = count( $rows );
		$rows    = array_filter( $rows, function ( $r ) use ( $cutoff ) {
			return (int) $r['last'] >= $cutoff;
		} );
		$deleted = $before - count( $rows );
		update_option( 'blz_events_fallback', $rows, false );
	}

	if ( $deleted ) {
		blz_scan_log( 'PRUNED ' . (int) $deleted . ' event record(s) older than ' . $days . ' days' );
	}
	return (int) $deleted;
}

/** Send mail without ever letting a mail failure reach the caller. */
function blz_safe_mail( $to, $subject, $body ) {
	if ( ! blz_alerts_enabled() || ! $to ) {
		return false;
	}
	try {
		return (bool) wp_mail( $to, $subject, $body );
	} catch ( Throwable $e ) {
		blz_scan_log( 'MAIL FAILED: ' . $e->getMessage() );
		return false;
	}
}

/** Immediate email for a critical event, rate-limited so a flood cannot spam. */
function blz_send_immediate_alert( $type, $entry ) {
	if ( ! blz_alerts_enabled() ) {
		return;
	}
	if ( get_transient( 'blz_alert_sent_' . $type ) ) {
		return;
	}
	set_transient( 'blz_alert_sent_' . $type, 1, HOUR_IN_SECONDS );

	$body = array(
		'A CRITICAL security event was recorded on ' . home_url() . '.',
		'',
		'Event:  ' . $type,
		'Detail: ' . $entry['detail'],
		'Actor:  ' . $entry['user'],
		'IP:     ' . $entry['ip'],
		'URI:    ' . $entry['uri'],
		'Agent:  ' . $entry['ua'],
		'Time:   ' . gmdate( 'Y-m-d H:i:s', $entry['time'] ) . ' UTC',
		'',
		'The attempt was blocked. Review: ' . admin_url( 'tools.php?page=blz-user-audit' ),
		'',
		'Repeats of this event type are suppressed for one hour and will appear',
		'in the daily digest instead.',
	);

	blz_safe_mail( blz_alert_recipient(), '[' . get_bloginfo( 'name' ) . '] CRITICAL: ' . $type, implode( "\n", $body ) );
}

/**
 * Send the daily digest, then mark those records notified.
 * Sends nothing when alerting is off, and nothing on a day with no real
 * attempt — a silent inbox is the correct output for a quiet day.
 */
function blz_send_digest( $context = 'cron' ) {
	if ( ! blz_alerts_enabled() ) {
		return false; // records stay pending, so turning alerts back on loses nothing
	}

	$rows = blz_collect_pending();
	if ( empty( $rows ) ) {
		return false;
	}

	$to = blz_alert_recipient();
	if ( ! $to ) {
		blz_mark_notified();
		return false;
	}

	$total    = 0;
	$critical = array();
	$notice   = array();
	foreach ( $rows as $r ) {
		$total += (int) $r->total;
		if ( 'critical' === $r->severity ) {
			$critical[] = $r;
		} else {
			$notice[] = $r;
		}
	}

	$lines   = array();
	$lines[] = 'Security digest for ' . home_url();
	$lines[] = 'Covering everything since the last digest — ' . $total . ' event(s).';
	$lines[] = '';

	$render = function ( $group, $heading ) use ( &$lines ) {
		if ( empty( $group ) ) {
			return;
		}
		$lines[] = strtoupper( $heading );
		$lines[] = str_repeat( '-', strlen( $heading ) );
		foreach ( $group as $r ) {
			$lines[] = $r->event_type . ' — ' . (int) $r->total . ' time(s)';
			$lines[] = '  First: ' . $r->first_seen . ' UTC   Last: ' . $r->last_seen . ' UTC';
			foreach ( blz_top_sources( $r->event_type ) as $src ) {
				$lines[] = '  Sources: ' . $src;
			}
			$lines[] = '';
		}
	};

	$render( $critical, 'Critical — act on these' );
	$render( $notice, 'Blocked attempts — no action needed' );

	$lines[] = 'Every event above was blocked. Full log: ' . admin_url( 'tools.php?page=blz-user-audit' );
	$lines[] = 'Records are kept for ' . (int) BLZ_LOG_RETENTION_DAYS . ' days, then deleted.';

	$subject = '[' . get_bloginfo( 'name' ) . '] Security digest';
	if ( ! empty( $critical ) ) {
		$subject = '[' . get_bloginfo( 'name' ) . '] Security digest — ' . count( $critical ) . ' CRITICAL';
	}

	if ( blz_safe_mail( $to, $subject, implode( "\n", $lines ) ) ) {
		blz_mark_notified();
		blz_scan_log( 'DIGEST sent (' . $context . '): ' . $total . ' event(s)' );
		return true;
	}

	// Mail failed — leave the records pending so tomorrow tries again.
	blz_scan_log( 'DIGEST could not be sent (' . $context . '); records left pending' );
	return false;
}

/** Busiest source IPs for one event type, as a single display line. */
function blz_top_sources( $type ) {
	global $wpdb;

	if ( blz_events_available() ) {
		$table    = blz_events_table();
		$suppress = $wpdb->suppress_errors( true );
		$tops     = $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, SUM(hits) AS n FROM {$table}
			 WHERE notified = 0 AND event_type = %s
			 GROUP BY ip ORDER BY n DESC LIMIT 5",
			$type
		) );
		$wpdb->suppress_errors( $suppress );

		if ( empty( $tops ) ) {
			return array();
		}
		$parts = array();
		foreach ( $tops as $t ) {
			$parts[] = $t->ip . ' (' . (int) $t->n . ')';
		}
		return array( implode( ', ', $parts ) );
	}

	$counts = array();
	foreach ( (array) get_option( 'blz_events_fallback', array() ) as $r ) {
		if ( ! empty( $r['notified'] ) || $r['type'] !== $type ) {
			continue;
		}
		$counts[ $r['ip'] ] = ( $counts[ $r['ip'] ] ?? 0 ) + (int) $r['hits'];
	}
	if ( empty( $counts ) ) {
		return array();
	}
	arsort( $counts );
	$parts = array();
	foreach ( array_slice( $counts, 0, 5, true ) as $ip => $n ) {
		$parts[] = $ip . ' (' . (int) $n . ')';
	}
	return array( implode( ', ', $parts ) );
}

/* =========================================================================
 * 10. TURN OFF EVERY PUBLIC REGISTRATION SWITCH
 * Forced at read time, so flipping the database row changes nothing.
 * ====================================================================== */

if ( ! blz_public_registration_allowed() ) {

	add_filter( 'pre_option_users_can_register', '__return_zero' );
	add_filter( 'option_users_can_register', '__return_zero' );

	add_action( 'login_init', function () {
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( 'register' === $action ) {
			blz_sec_event( 'blocked_register_page', 'Hit on wp-login.php?action=register', false );
			wp_die( 'Registration is disabled on this site.', 'Registration disabled', array( 'response' => 403 ) );
		}
	}, 1 );

	add_filter( 'register_url', function () {
		return home_url( '/' );
	} );
	add_action( 'register_form', function () {
		wp_die( 'Registration is disabled on this site.', 'Registration disabled', array( 'response' => 403 ) );
	}, 1 );

	$blz_no = function () {
		return 'no';
	};
	add_filter( 'pre_option_woocommerce_enable_myaccount_registration', $blz_no );
	add_filter( 'pre_option_woocommerce_enable_signup_and_login_from_checkout', $blz_no );
	add_filter( 'woocommerce_registration_enabled', '__return_false', 99 );
	add_filter( 'woocommerce_checkout_registration_enabled', '__return_false', 99 );
}

// Never let default_role drift to something privileged.
add_filter( 'option_default_role', function ( $role ) {
	if ( in_array( $role, blz_privileged_roles(), true ) || blz_caps_are_privileged( array( $role => true ) ) ) {
		return 'subscriber';
	}
	return $role;
} );

/* =========================================================================
 * 11. THE WALL — no account is created unless an admin is doing it
 *
 * wp_pre_insert_user_data fires inside wp_insert_user() immediately before the
 * INSERT, on every path: wp_create_user(), REST, XML-RPC, WooCommerce, AJAX,
 * and any plugin that calls the core API. Returning a non-array makes
 * wp_insert_user() bail with WP_Error( 'empty_data' ) — no fatal, no half row.
 * ====================================================================== */

add_filter( 'wp_pre_insert_user_data', function ( $data, $update, $user_id, $userdata ) {

	if ( $update ) {
		return $data; // profile updates are covered by the capability guard below
	}

	$login = is_array( $userdata ) ? (string) ( $userdata['user_login'] ?? '' ) : '';
	$email = is_array( $userdata ) ? (string) ( $userdata['user_email'] ?? '' ) : '';
	$label = $login . ( $email ? ' <' . $email . '>' : '' );

	if ( blz_user_write_authorized() ) {
		blz_sec_event( 'user_created', 'New user created by an authorised administrator: ' . $label, true );
		return $data;
	}

	if ( blz_public_registration_allowed() ) {
		blz_sec_event( 'public_signup', 'Public registration (allowed by config): ' . $label, false );
		return $data;
	}

	blz_sec_event( 'blocked_create', 'BLOCKED unauthorised user creation: ' . $label, true );
	return array();
}, 5, 4 );

// Belt and braces: refuse at the validation layer so forms show an error.
add_filter( 'registration_errors', function ( $errors ) {
	if ( ! blz_user_write_authorized() && ! blz_public_registration_allowed() ) {
		$errors->add( 'blz_registration_disabled', '<strong>ERROR</strong>: Registration is disabled on this site.' );
	}
	return $errors;
}, 1 );

add_filter( 'woocommerce_registration_errors', function ( $errors ) {
	if ( ! blz_user_write_authorized() && ! blz_public_registration_allowed() ) {
		$errors->add( 'blz_registration_disabled', 'Registration is disabled on this site.' );
	}
	return $errors;
}, 1 );

// Public signups (when re-enabled) are forced down to a harmless role.
add_action( 'user_register', function ( $new_user_id ) {
	if ( blz_user_write_authorized() ) {
		return;
	}
	$user = get_userdata( $new_user_id );
	$role = blz_public_role();
	if ( $user && ! in_array( $role, (array) $user->roles, true ) ) {
		$user->set_role( $role );
	}
}, 1 );

/* =========================================================================
 * 12. PRIVILEGE ESCALATION GUARD
 * Roles live in the {prefix}capabilities user meta. set_role(), add_role(),
 * update_user_meta() and the REST user endpoints all write that key, so one
 * guard on the metadata API covers every route in core.
 * ====================================================================== */

function blz_is_caps_meta_key( $meta_key ) {
	global $wpdb;
	if ( 0 !== strpos( (string) $meta_key, $wpdb->base_prefix ) ) {
		return false;
	}
	// Matches wp_capabilities, wp_2_capabilities, wp_user_level, ...
	return (bool) preg_match( '/(capabilities|user_level)$/', (string) $meta_key );
}

function blz_guard_caps_meta( $check, $object_id, $meta_key, $meta_value ) {
	if ( null !== $check ) {
		return $check; // someone else already short-circuited
	}
	if ( ! blz_is_caps_meta_key( $meta_key ) ) {
		return $check;
	}

	// Same story as the role table: update_metadata() fires this filter before
	// it checks whether anything actually changed. Re-asserting the value a
	// user already has is not an escalation attempt.
	$existing = get_user_meta( $object_id, $meta_key, true );
	if ( '' !== $existing && maybe_serialize( $existing ) === maybe_serialize( $meta_value ) ) {
		return $check;
	}

	$is_level     = ( substr( (string) $meta_key, -10 ) === 'user_level' );
	$is_dangerous = $is_level ? ( (int) $meta_value > 1 ) : blz_caps_are_privileged( $meta_value );

	if ( blz_user_write_authorized() ) {
		if ( $is_dangerous ) {
			$target = get_userdata( $object_id );
			blz_sec_event(
				'privilege_granted',
				'Administrator granted privileged capabilities to user #' . (int) $object_id
					. ( $target ? ' (' . $target->user_login . ')' : '' ),
				true
			);
		}
		return $check;
	}

	if ( ! $is_dangerous ) {
		return $check; // subscriber/customer level changes are harmless
	}

	$target = get_userdata( $object_id );
	blz_sec_event(
		'blocked_escalation',
		'BLOCKED privilege escalation on user #' . (int) $object_id
			. ( $target ? ' (' . $target->user_login . ')' : '' )
			. ' via meta key ' . $meta_key,
		true
	);

	return false; // short-circuits the metadata write
}

add_filter( 'update_user_metadata', function ( $check, $object_id, $meta_key, $meta_value ) {
	return blz_guard_caps_meta( $check, $object_id, $meta_key, $meta_value );
}, 5, 4 );

add_filter( 'add_user_metadata', function ( $check, $object_id, $meta_key, $meta_value ) {
	return blz_guard_caps_meta( $check, $object_id, $meta_key, $meta_value );
}, 5, 4 );

// Deny the user-management capabilities themselves to anyone who is not a real
// administrator, so a plugin that hands create_users to an editor (or an
// attacker who edits a role) still gets nowhere.
add_filter( 'map_meta_cap', function ( $caps, $cap, $user_id, $args ) {
	$guarded = array(
		'create_users', 'edit_users', 'delete_users', 'promote_users', 'remove_users', 'add_users', 'list_users',
		'edit_user', 'delete_user', 'promote_user', 'remove_user', 'add_user',
	);
	if ( ! in_array( $cap, $guarded, true ) ) {
		return $caps;
	}
	// Editing your own account is always fine — customers need this.
	if ( isset( $args[0] ) && (int) $args[0] === (int) $user_id ) {
		return $caps;
	}
	if ( is_multisite() && function_exists( 'is_super_admin' ) && is_super_admin( $user_id ) ) {
		return $caps;
	}
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return array( 'do_not_allow' );
	}
	if ( array_intersect( blz_privileged_roles(), (array) $user->roles ) ) {
		return $caps;
	}
	return array( 'do_not_allow' );
}, 10, 4 );

/* =========================================================================
 * 13. ROLE-DEFINITION TAMPERING ({prefix}user_roles)
 * Rewriting this option is how "subscriber, but with manage_options" happens.
 * ====================================================================== */

$blz_role_key = $GLOBALS['wpdb']->get_blog_prefix() . 'user_roles';

/**
 * The role table as it actually sits in the database, bypassing our own
 * option_ read filter. Comparing against the FILTERED value would make every
 * stripped capability look like an attempt to add one.
 */
function blz_raw_role_option() {
	global $wpdb;
	$key      = $wpdb->get_blog_prefix() . 'user_roles';
	$suppress = $wpdb->suppress_errors( true );
	$raw      = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key ) );
	$wpdb->suppress_errors( $suppress );
	return is_string( $raw ) ? maybe_unserialize( $raw ) : array();
}

/**
 * Does this write actually grant an escalation capability to a role that did
 * not already have it? Plugins rewrite this option constantly as routine
 * housekeeping; only a genuine privilege grant is worth blocking.
 *
 * @return string|false the offending "role:capability", or false if benign.
 */
function blz_role_write_escalates( $new, $old ) {
	if ( ! is_array( $new ) ) {
		return false;
	}
	$old    = is_array( $old ) ? $old : array();
	$exempt = blz_privileged_roles();
	$danger = blz_escalation_caps();

	foreach ( $new as $slug => $role ) {
		if ( in_array( $slug, $exempt, true ) || empty( $role['capabilities'] ) ) {
			continue;
		}
		foreach ( $danger as $cap ) {
			$granted_now    = ! empty( $role['capabilities'][ $cap ] );
			$granted_before = ! empty( $old[ $slug ]['capabilities'][ $cap ] );
			if ( $granted_now && ! $granted_before ) {
				return $slug . ':' . $cap;
			}
		}
	}
	return false;
}

add_filter( 'pre_update_option_' . $blz_role_key, function ( $value, $old_value ) {
	if ( blz_user_write_authorized() ) {
		return $value;
	}

	$raw = blz_raw_role_option();

	// No-op write. update_option() fires this filter BEFORE comparing old and
	// new, so a plugin that re-asserts capabilities it already granted lands
	// here on every request even though WordPress writes nothing. EventON's
	// eventon_init_caps() does exactly this, 20 times per page load. There is
	// no change to judge, so say nothing.
	if ( maybe_serialize( $value ) === maybe_serialize( $raw ) ) {
		return $value;
	}

	$escalation = blz_role_write_escalates( $value, $raw );

	if ( false === $escalation ) {
		// Routine: a plugin re-registering its roles or adjusting a harmless
		// capability. Allowed, recorded at info level, never emailed — this is
		// what a crawler hitting /robots.txt used to trigger.
		blz_sec_event( 'role_table_write', 'Role table rewritten by ' . blz_guilty_file(), false );
		return $value;
	}

	blz_sec_event(
		'blocked_role_edit',
		'BLOCKED privilege grant in the role table (' . $escalation . ') from ' . blz_guilty_file(),
		true
	);
	return $old_value;
}, 10, 2 );

if ( BLZ_LOCK_ROLE_CAPS ) {
	add_filter( 'option_' . $blz_role_key, function ( $roles ) {
		if ( ! is_array( $roles ) ) {
			return $roles;
		}
		$exempt = blz_privileged_roles();
		$danger = blz_escalation_caps();
		foreach ( $roles as $slug => $role ) {
			if ( in_array( $slug, $exempt, true ) || empty( $role['capabilities'] ) ) {
				continue;
			}
			foreach ( $danger as $cap ) {
				if ( isset( $roles[ $slug ]['capabilities'][ $cap ] ) ) {
					unset( $roles[ $slug ]['capabilities'][ $cap ] );
				}
			}
		}
		return $roles;
	} );
}

/* =========================================================================
 * 14. REST API
 * Anonymous access is refused except for the routes in BLZ_PUBLIC_REST_ROUTES.
 * Matching is on the ROUTE, so a query string cannot fake it.
 * ====================================================================== */

function blz_rest_current_route() {
	if ( ! empty( $_GET['rest_route'] ) ) {
		return '/' . ltrim( sanitize_text_field( wp_unslash( $_GET['rest_route'] ) ), '/' );
	}
	$path   = (string) parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
	$prefix = '/' . ( function_exists( 'rest_get_url_prefix' ) ? rest_get_url_prefix() : 'wp-json' ) . '/';
	$pos    = strpos( $path, $prefix );
	if ( false === $pos ) {
		return '';
	}
	return '/' . ltrim( substr( $path, $pos + strlen( $prefix ) ), '/' );
}

function blz_rest_route_matches( $route, $list ) {
	foreach ( (array) $list as $prefix ) {
		if ( '' !== $prefix && 0 === strpos( $route, $prefix ) ) {
			return true;
		}
	}
	return false;
}

function blz_rest_route_is_public() {
	$route = blz_rest_current_route();
	if ( '' === $route ) {
		return false;
	}
	if ( blz_rest_route_matches( $route, BLZ_REST_DENY_ROUTES ) ) {
		return false;
	}
	return blz_rest_route_matches( $route, BLZ_PUBLIC_REST_ROUTES );
}

add_filter( 'rest_authentication_errors', function ( $result ) {
	if ( ! empty( $result ) || is_user_logged_in() ) {
		return $result;
	}
	if ( blz_rest_route_is_public() ) {
		return $result;
	}
	return new WP_Error( 'rest_forbidden', 'Restricted.', array( 'status' => 401 ) );
}, 5 );

// Any REST route that writes to users needs a real administrator, whoever
// registered it. Self-service profile edits are still allowed.
// Authoritative anonymous gate. rest_authentication_errors runs before the
// route is resolved, so it has to infer the route from the request. This runs
// after resolution, where get_route() is exactly what will be dispatched —
// any mismatch between the two is closed here.
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	if ( ! empty( $result ) || is_user_logged_in() ) {
		return $result;
	}
	$route = (string) $request->get_route();
	if ( blz_rest_route_matches( $route, BLZ_REST_DENY_ROUTES )
		|| ! blz_rest_route_matches( $route, BLZ_PUBLIC_REST_ROUTES ) ) {
		return new WP_Error( 'rest_forbidden', 'Restricted.', array( 'status' => 401 ) );
	}
	return $result;
}, 5, 3 );

add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$route  = (string) $request->get_route();
	$method = strtoupper( (string) $request->get_method() );

	if ( ! preg_match( '#/users(/|$)#i', $route ) ) {
		return $result;
	}
	if ( in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true ) ) {
		return $result;
	}
	if ( blz_user_write_authorized() ) {
		return $result;
	}

	$self = get_current_user_id();
	if ( $self && preg_match( '#/users/(me|' . $self . ')$#i', $route ) && 'DELETE' !== $method ) {
		return $result;
	}

	blz_sec_event( 'blocked_rest_users', 'BLOCKED ' . $method . ' ' . $route, true );
	return new WP_Error( 'blz_users_locked', 'User management is restricted.', array( 'status' => 403 ) );
}, 10, 3 );

// Remove the core user endpoints entirely (defence in depth).
add_filter( 'rest_endpoints', function ( $endpoints ) {
	unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
	return $endpoints;
} );

/* =========================================================================
 * 15. XML-RPC — HARD BLOCK
 * xmlrpc_enabled=false only disables authenticated methods; the endpoint still
 * loads and answers. These rules refuse the request outright.
 * ====================================================================== */

// xmlrpc.php defines XMLRPC_REQUEST before bootstrapping, so this catches it.
if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
	header( 'HTTP/1.1 403 Forbidden' );
	exit( 'XML-RPC services are disabled on this site.' );
}

add_filter( 'xmlrpc_enabled', '__return_false' );
add_filter( 'xmlrpc_methods', '__return_empty_array' );
add_filter( 'pre_update_option_enable_xmlrpc', '__return_false' );

add_filter( 'wp_headers', function ( $headers ) {
	unset( $headers['X-Pingback'] );
	return $headers;
} );
add_filter( 'bloginfo_url', function ( $output, $show ) {
	return ( 'pingback_url' === $show ) ? '' : $output;
}, 10, 2 );

/* =========================================================================
 * 16. AUTHOR / USERNAME LEAK PROTECTION
 * ====================================================================== */

add_filter( 'wp_sitemaps_add_provider', function ( $provider, $name ) {
	return ( 'users' === $name ) ? false : $provider;
}, 10, 2 );

// Block ?author=N enumeration BEFORE the canonical redirect leaks the slug.
add_action( 'parse_request', function ( $wp ) {
	if ( is_admin() ) {
		return;
	}
	if ( isset( $_GET['author'] ) && preg_match( '/\d/', (string) $_GET['author'] ) ) {
		wp_safe_redirect( home_url( '/' ), 302 );
		exit;
	}
} );

// Stop the canonical redirect ?author=1 -> /author/{login}/ (Location leak).
add_filter( 'redirect_canonical', function ( $redirect_url ) {
	if ( is_author() ) {
		return false;
	}
	return $redirect_url;
} );

add_action( 'template_redirect', function () {
	if ( is_author() ) {
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
	}
} );

add_filter( 'author_link', function () {
	return home_url( '/' );
} );

// Mask author display names on the front end so a display_name equal to a real
// login cannot be harvested.
if ( ! BLZ_SHOW_AUTHOR ) {
	$blz_mask_author = function () {
		return get_bloginfo( 'name' );
	};
	add_filter( 'the_author', $blz_mask_author, 99 );
	add_filter( 'the_author_display_name', $blz_mask_author, 99 );
	add_filter( 'get_the_author_display_name', $blz_mask_author, 99 );

	add_filter( 'body_class', function ( $classes ) {
		return array_values( array_filter( $classes, function ( $c ) {
			return strpos( $c, 'author-' ) !== 0;
		} ) );
	} );

	add_filter( 'oembed_response_data', function ( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	} );
}

/* =========================================================================
 * 17. STANDARD CLEANUP + SECURITY HEADERS
 * ====================================================================== */

add_filter( 'wp_is_application_passwords_available', '__return_false' );

remove_action( 'wp_head', 'wp_generator' );
remove_action( 'wp_head', 'rsd_link' );
remove_action( 'wp_head', 'wlwmanifest_link' );
remove_action( 'wp_head', 'wp_shortlink_wp_head' );
add_filter( 'the_generator', '__return_empty_string' );

// Blocks one-click malware injection via a stolen admin session.
if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
	define( 'DISALLOW_FILE_EDIT', true );
}

// Generic login errors (don't reveal whether a username exists), but keep our
// own security-check messages so humans know to retry the CAPTCHA.
add_filter( 'login_errors', function ( $message ) {
	global $errors;
	if ( is_wp_error( $errors ) ) {
		foreach ( $errors->get_error_codes() as $code ) {
			if ( 0 === strpos( (string) $code, 'blz_' ) ) {
				return $message;
			}
		}
	}
	return 'Invalid credentials.';
} );

add_action( 'send_headers', function () {
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );

	// HSTS can lock a domain to HTTPS. Enable only when every subdomain is
	// HTTPS-only.
	if ( is_ssl() && BLZ_ENABLE_HSTS ) {
		header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
	}
} );

/* =========================================================================
 * 18. CUSTOM LOGIN URL (optional)
 * Set BLZ_LOGIN_SLUG above. Empty = wp-login.php behaves normally.
 * Runs on plugins_loaded, which is where wp-login.php can safely be handed
 * control (pluggable.php is available and the request has not been routed yet).
 * ====================================================================== */

function blz_login_slug() {
	return BLZ_LOGIN_SLUG ? trim( (string) BLZ_LOGIN_SLUG, '/' ) : '';
}

/** Current request path relative to the WordPress install (handles subdirs). */
function blz_request_path() {
	$path = parse_url( $_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH );
	$path = trim( (string) $path, '/' );

	$home = trim( (string) parse_url( home_url(), PHP_URL_PATH ), '/' );
	if ( '' !== $home && strpos( $path, $home ) === 0 ) {
		$path = trim( substr( $path, strlen( $home ) ), '/' );
	}
	return $path;
}

function blz_login_not_found() {
	status_header( 404 );
	nocache_headers();
	wp_die( 'Page not found.', 'Not Found', array( 'response' => 404 ) );
}

/** Rewrite WordPress-generated wp-login.php URLs to the secret slug. */
function blz_swap_login_url( $url ) {
	$slug = blz_login_slug();
	if ( $slug && strpos( (string) $url, 'wp-login.php' ) !== false ) {
		$url = str_replace( 'wp-login.php', $slug, $url );
	}
	return $url;
}

if ( blz_login_slug() ) {

	// Detection only. The actual handoff waits for wp_loaded, because
	// wp-settings.php defines AUTOSAVE_INTERVAL and friends via
	// wp_functionality_constants() AFTER plugins_loaded fires — rendering the
	// login page here throws "Undefined constant AUTOSAVE_INTERVAL" and gives
	// plugins that initialise on init no chance to set themselves up.
	add_action( 'plugins_loaded', function () {
		global $pagenow;

		$slug   = blz_login_slug();
		$path   = blz_request_path();
		$script = basename( $_SERVER['SCRIPT_NAME'] ?? '' );

		// (A) Secret slug requested -> mark it; wp-login.php loads at wp_loaded.
		if ( $path === $slug ) {
			if ( ! defined( 'BLZ_DOING_LOGIN' ) ) {
				define( 'BLZ_DOING_LOGIN', true );
			}
			$pagenow = 'wp-login.php'; // some plugins branch on this
			return;
		}

		// (B) Direct hit on the real wp-login.php -> flag it for a 404.
		if ( 'wp-login.php' === $script && ! defined( 'BLZ_DOING_LOGIN' ) ) {
			$GLOBALS['blz_block_wp_login'] = true;
		}
	}, 1 );

	// wp_loaded is the last thing wp-settings.php does: every constant is
	// defined, the theme is loaded, and the request has not been parsed yet.
	add_action( 'wp_loaded', function () {
		if ( defined( 'BLZ_DOING_LOGIN' ) && BLZ_DOING_LOGIN ) {
			require_once ABSPATH . 'wp-login.php';
			exit;
		}
		if ( ! empty( $GLOBALS['blz_block_wp_login'] ) ) {
			blz_login_not_found();
		}
	}, 1 );

	// (C) Logged-out wp-admin access -> 404 instead of leaking the slug via an
	// auth redirect. Ajax and admin-post are left alone.
	add_action( 'init', function () {
		if ( ! is_admin() || is_user_logged_in() || wp_doing_ajax() ) {
			return;
		}
		if ( basename( $_SERVER['SCRIPT_NAME'] ?? '' ) === 'admin-post.php' ) {
			return;
		}
		blz_login_not_found();
	} );

	// (D) Keep all core-generated login URLs pointed at the secret slug.
	add_filter( 'login_url', 'blz_swap_login_url' );
	add_filter( 'logout_url', 'blz_swap_login_url' );
	add_filter( 'lostpassword_url', 'blz_swap_login_url' );
	add_filter( 'register_url', 'blz_swap_login_url' );
	add_filter( 'wp_redirect', 'blz_swap_login_url' );
	add_filter( 'site_url', function ( $url, $path ) {
		return ( 'wp-login.php' === $path || strpos( (string) $path, 'wp-login.php?' ) === 0 )
			? blz_swap_login_url( $url ) : $url;
	}, 10, 2 );
	add_filter( 'network_site_url', function ( $url, $path ) {
		return ( strpos( (string) $path, 'wp-login.php' ) === 0 )
			? blz_swap_login_url( $url ) : $url;
	}, 10, 2 );
}

/* =========================================================================
 * 19. INTEGRITY & MALWARE SCANNER
 *
 *   Core files: every core file compared against the official MD5 list from
 *               api.wordpress.org via core's own get_core_checksums() — the
 *               same data WP-CLI uses, but in-process, so it works on shared
 *               hosting with no shell access. REPORT ONLY.
 *   Uploads:    executable PHP dropped in /uploads/ (a classic backdoor) is
 *               quarantined (neutralised + logged) and permanently deleted
 *               after a grace period.
 *
 * Runs daily via WP-Cron and on demand from Tools -> Security Scan.
 * ====================================================================== */

function blz_scan_enabled() {
	return (bool) BLZ_SECURITY_SCAN;
}

/** Quarantine directory (created on demand) with its own deny-all guard. */
function blz_quarantine_dir() {
	$uploads = wp_get_upload_dir();
	$base    = $uploads['basedir'] ?? '';
	if ( ! $base ) {
		return '';
	}
	$dir = trailingslashit( $base ) . '.blz-quarantine';
	if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
		return '';
	}
	$ht = trailingslashit( $dir ) . '.htaccess';
	if ( ! file_exists( $ht ) ) {
		@file_put_contents( $ht, "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
	}
	$idx = trailingslashit( $dir ) . 'index.html';
	if ( ! file_exists( $idx ) ) {
		@file_put_contents( $idx, '' );
	}
	return $dir;
}

function blz_scan_log( $message ) {
	$dir = blz_quarantine_dir();
	if ( ! $dir ) {
		return;
	}
	$log = trailingslashit( $dir ) . 'scan.log';

	// Rotate at 2 MB, keeping one previous file. Without this the log grows
	// forever on a site under steady bot pressure.
	if ( file_exists( $log ) && filesize( $log ) > 2 * MB_IN_BYTES ) {
		@rename( $log, $log . '.1' );
	}

	$line = '[' . gmdate( 'Y-m-d H:i:s' ) . ' UTC] ' . $message . "\n";
	@file_put_contents( $log, $line, FILE_APPEND | LOCK_EX );
}

/**
 * Core file integrity — report only.
 * @return array{modified:string[],missing:string[],unknown:string[],error:string}
 */
function blz_scan_core_integrity() {
	$result = array( 'modified' => array(), 'missing' => array(), 'unknown' => array(), 'error' => '' );
	if ( ! BLZ_CORE_SCAN ) {
		return $result;
	}

	if ( ! function_exists( 'get_core_checksums' ) ) {
		require_once ABSPATH . 'wp-admin/includes/update.php';
	}

	global $wp_version;
	$locale    = get_locale();
	$checksums = get_core_checksums( $wp_version, empty( $locale ) ? 'en_US' : $locale );
	if ( ! is_array( $checksums ) ) {
		$checksums = get_core_checksums( $wp_version, 'en_US' );
	}
	if ( ! is_array( $checksums ) ) {
		$result['error'] = 'Could not fetch checksums from api.wordpress.org for version ' . $wp_version . '.';
		return $result;
	}

	$known = array();
	foreach ( $checksums as $file => $md5 ) {
		$known[ $file ] = true;

		// Skip bundled themes/plugins — they churn and cause false positives.
		if ( strpos( $file, 'wp-content/' ) === 0 ) {
			continue;
		}
		$path = ABSPATH . $file;
		if ( ! file_exists( $path ) ) {
			$result['missing'][] = $file;
		} elseif ( md5_file( $path ) !== $md5 ) {
			$result['modified'][] = $file;
		}
	}

	// Unknown *.php inside core directories = prime backdoor indicator.
	foreach ( array( 'wp-admin', WPINC ) as $sub ) {
		$root = ABSPATH . $sub;
		if ( ! is_dir( $root ) ) {
			continue;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
			);
		} catch ( Exception $e ) {
			continue;
		}
		foreach ( $it as $file ) {
			if ( ! $file->isFile() || strtolower( $file->getExtension() ) !== 'php' ) {
				continue;
			}
			$rel = str_replace( '\\', '/', ltrim( str_replace( ABSPATH, '', $file->getPathname() ), '/\\' ) );
			if ( ! isset( $known[ $rel ] ) ) {
				$result['unknown'][] = $rel;
			}
		}
	}

	return $result;
}

/** Move one file into quarantine (extension stripped + chmod 000) and record it. */
function blz_quarantine_file( $path, $rel ) {
	$dir = blz_quarantine_dir();
	if ( ! $dir ) {
		return false;
	}
	$dest = trailingslashit( $dir ) . md5( $path . microtime() ) . '.' . basename( $path ) . '.quar';

	if ( ! @rename( $path, $dest ) ) {
		if ( ! ( @copy( $path, $dest ) && @unlink( $path ) ) ) {
			return false;
		}
	}
	@chmod( $dest, 0000 );

	$manifest   = get_option( 'blz_quarantine', array() );
	$manifest[] = array( 'orig' => $rel, 'quar' => $dest, 'time' => time() );
	update_option( 'blz_quarantine', $manifest, false );

	blz_scan_log( 'QUARANTINED uploads PHP: ' . $rel . ' -> ' . basename( $dest ) );
	return true;
}

/**
 * Scan /uploads/ for executable PHP and quarantine it.
 * @return array{quarantined:string[],errors:string[]}
 */
function blz_scan_uploads() {
	$result = array( 'quarantined' => array(), 'errors' => array() );
	if ( ! BLZ_UPLOADS_SCAN ) {
		return $result;
	}

	$uploads = wp_get_upload_dir();
	$base    = $uploads['basedir'] ?? '';
	if ( ! $base || ! is_dir( $base ) ) {
		return $result;
	}

	$quar  = blz_quarantine_dir();
	$allow = ( defined( 'BLZ_UPLOADS_PHP_ALLOWLIST' ) && is_array( BLZ_UPLOADS_PHP_ALLOWLIST ) ) ? BLZ_UPLOADS_PHP_ALLOWLIST : array();

	try {
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);
	} catch ( Exception $e ) {
		$result['errors'][] = $e->getMessage();
		return $result;
	}

	foreach ( $it as $file ) {
		if ( ! $file->isFile() ) {
			continue;
		}
		$path = $file->getPathname();
		if ( $quar && strpos( $path, $quar ) === 0 ) {
			continue; // never touch our own quarantine
		}
		if ( ! preg_match( '/\.(php|phtml|php\d|phps|pht|phar)$/i', $file->getFilename() ) ) {
			continue;
		}

		// WordPress and many plugins drop a blank index.php into upload
		// folders to prevent directory listing. Quarantining those would
		// break nothing but would bury real findings in noise — and deleting
		// them after the grace period re-opens directory listing.
		if ( blz_is_harmless_index_php( $file ) ) {
			continue;
		}

		$rel = str_replace( '\\', '/', ltrim( str_replace( $base, '', $path ), '/\\' ) );
		if ( in_array( $rel, $allow, true ) ) {
			continue;
		}

		if ( blz_quarantine_file( $path, $rel ) ) {
			$result['quarantined'][] = $rel;
		} else {
			$result['errors'][] = 'Failed to quarantine: ' . $rel;
		}
	}

	return $result;
}

/**
 * A blank "silence is golden" index.php is a guard file, not a backdoor.
 * Anything with real code in it is treated as suspicious regardless of name.
 */
function blz_is_harmless_index_php( $file ) {
	if ( strtolower( $file->getFilename() ) !== 'index.php' ) {
		return false;
	}
	if ( $file->getSize() > 200 ) {
		return false;
	}
	$body = @file_get_contents( $file->getPathname() );
	if ( false === $body ) {
		return false;
	}
	$body = trim( $body );
	// Allow: empty, a bare open tag, or an open tag plus one comment line.
	return (bool) preg_match( '#^(<\?php)?\s*(//[^\n]*|/\*.*?\*/|\#[^\n]*)?\s*$#s', $body );
}

/**
 * Drop a deny-PHP guard into /uploads/. This is the control that actually
 * matters: the scanner finds a backdoor after the fact, this stops it
 * executing in the first place. Apache and LiteSpeed honour .htaccess;
 * on nginx it does nothing, so the rule must go in the server config.
 */
function blz_harden_uploads_dir() {
	if ( ! BLZ_HARDEN_UPLOADS_DIR ) {
		return;
	}
	$uploads = wp_get_upload_dir();
	$base    = $uploads['basedir'] ?? '';
	if ( ! $base || ! is_dir( $base ) ) {
		return;
	}

	$file  = trailingslashit( $base ) . '.htaccess';
	$rules = "# Added by AAA Site Security — block execution of scripts in uploads.\n"
		. "<FilesMatch \"\\.(?i:php|phtml|php3|php4|php5|php7|php8|phps|pht|phar|cgi|pl|py|asp|aspx|shtml)$\">\n"
		. "\tRequire all denied\n"
		. "\t<IfModule !mod_authz_core.c>\n"
		. "\t\tDeny from all\n"
		. "\t</IfModule>\n"
		. "</FilesMatch>\n"
		. "<IfModule mod_php.c>\n\tphp_flag engine off\n</IfModule>\n"
		. "<IfModule mod_php7.c>\n\tphp_flag engine off\n</IfModule>\n"
		. "<IfModule mod_php8.c>\n\tphp_flag engine off\n</IfModule>\n";

	$existing = file_exists( $file ) ? (string) @file_get_contents( $file ) : '';
	if ( false !== strpos( $existing, 'AAA Site Security' ) ) {
		return; // already in place
	}
	@file_put_contents( $file, $existing . ( '' === $existing ? '' : "\n" ) . $rules, LOCK_EX );
	blz_scan_log( 'HARDENED uploads directory with a deny-PHP .htaccess' );
}

/**
 * Refuse uploads with an executable extension outright. Catches the double
 * extension trick (shell.php.jpg) that some MIME checks let through.
 */
add_filter( 'wp_handle_upload_prefilter', function ( $file ) {
	if ( ! BLZ_BLOCK_PHP_UPLOADS ) {
		return $file;
	}
	$name = strtolower( (string) ( $file['name'] ?? '' ) );
	if ( preg_match( '/\.(php|phtml|php\d|phps|pht|phar|cgi|pl|py|asp|aspx|jsp|shtml|htaccess)(\.|$)/i', $name ) ) {
		blz_sec_event( 'blocked_upload', 'BLOCKED upload of an executable file: ' . $name, true );
		$file['error'] = 'This file type is not permitted.';
	}
	return $file;
} );
function blz_purge_quarantine() {
	$days     = (int) BLZ_UPLOADS_QUARANTINE_DAYS;
	$cutoff   = time() - $days * DAY_IN_SECONDS;
	$manifest = get_option( 'blz_quarantine', array() );
	if ( empty( $manifest ) ) {
		return array();
	}

	$purged = array();
	$keep   = array();
	foreach ( $manifest as $entry ) {
		if ( (int) ( $entry['time'] ?? 0 ) < $cutoff ) {
			if ( ! empty( $entry['quar'] ) && file_exists( $entry['quar'] ) ) {
				@chmod( $entry['quar'], 0644 );
				@unlink( $entry['quar'] );
			}
			$purged[] = $entry['orig'] ?? '';
			blz_scan_log( 'PURGED quarantined file (>' . $days . 'd): ' . ( $entry['orig'] ?? '' ) );
		} else {
			$keep[] = $entry;
		}
	}
	if ( count( $keep ) !== count( $manifest ) ) {
		update_option( 'blz_quarantine', $keep, false );
	}
	return $purged;
}

function blz_notify_findings( $report ) {
	$c = $report['core'];
	$u = $report['uploads'];

	// Findings are raised as events so they inherit the digest/critical rules
	// rather than sending their own separate email every single day.
	if ( ! empty( $u['quarantined'] ) ) {
		blz_sec_event( 'backdoor_quarantined',
			count( $u['quarantined'] ) . ' executable PHP file(s) found in /uploads/ and quarantined: '
				. implode( ', ', array_slice( $u['quarantined'], 0, 5 ) ), true );
	}
	if ( ! empty( $c['modified'] ) ) {
		blz_sec_event( 'core_files_modified',
			count( $c['modified'] ) . ' core file(s) do not match the official checksums: '
				. implode( ', ', array_slice( $c['modified'], 0, 5 ) ), true );
	}
	if ( ! empty( $c['unknown'] ) ) {
		blz_sec_event( 'unknown_core_files',
			count( $c['unknown'] ) . ' unrecognised PHP file(s) in core directories: '
				. implode( ', ', array_slice( $c['unknown'], 0, 5 ) ), true );
	}
	if ( ! empty( $c['missing'] ) ) {
		blz_sec_event( 'core_files_missing',
			count( $c['missing'] ) . ' core file(s) are missing: '
				. implode( ', ', array_slice( $c['missing'], 0, 5 ) ), true );
	}
	if ( ! empty( $c['error'] ) ) {
		blz_sec_event( 'core_check_error', $c['error'], true );
	}
}

/** Orchestrate a full scan, persist the report, log, and notify. */
function blz_run_all_scans( $context = 'cron' ) {
	if ( ! blz_scan_enabled() ) {
		return null;
	}
	if ( get_transient( 'blz_scan_running' ) ) {
		return get_option( 'blz_scan_report' );
	}
	set_transient( 'blz_scan_running', 1, 10 * MINUTE_IN_SECONDS );
	@set_time_limit( 0 );

	blz_harden_uploads_dir();

	$core    = blz_scan_core_integrity();
	$uploads = blz_scan_uploads();
	$purged  = blz_purge_quarantine();

	$has = ! empty( $core['modified'] ) || ! empty( $core['missing'] ) || ! empty( $core['unknown'] )
		|| ! empty( $core['error'] ) || ! empty( $uploads['quarantined'] );

	$report = array(
		'time'         => time(),
		'context'      => $context,
		'core'         => $core,
		'uploads'      => $uploads,
		'purged'       => $purged,
		'has_findings' => $has,
	);
	update_option( 'blz_scan_report', $report, false );

	blz_scan_log( sprintf(
		'SCAN (%s): core modified=%d missing=%d unknown=%d; uploads quarantined=%d; purged=%d',
		$context, count( $core['modified'] ), count( $core['missing'] ), count( $core['unknown'] ),
		count( $uploads['quarantined'] ), count( $purged )
	) );

	if ( $has ) {
		blz_notify_findings( $report );
	}

	delete_transient( 'blz_scan_running' );
	return $report;
}

/* =========================================================================
 * 20. ADMIN-ROSTER CHECK
 * Catches an account that gains the administrator role by a route the hooks
 * cannot see — direct SQL from a backdoor, for example.
 * ====================================================================== */

function blz_audit_admin_roster() {
	$admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login', 'user_email' ) ) );
	$now    = array();
	foreach ( $admins as $a ) {
		$now[ (int) $a->ID ] = $a->user_login . ' <' . $a->user_email . '>';
	}

	$known = get_option( 'blz_known_admins', null );
	if ( ! is_array( $known ) ) {
		update_option( 'blz_known_admins', $now, false ); // first run seeds the baseline
		return;
	}

	$new = array_diff_key( $now, $known );
	if ( ! empty( $new ) ) {
		blz_sec_event( 'new_admin_detected', 'Administrator account(s) not in the known list: ' . implode( ', ', $new ), true );
	}
	update_option( 'blz_known_admins', $now, false );
}

/**
 * Invalidate every logged-in session on the site.
 * Changing passwords does not evict an attacker who already holds a valid
 * auth cookie; deleting the session tokens does.
 */
function blz_destroy_all_sessions() {
	global $wpdb;
	$ids = $wpdb->get_col( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'" );
	foreach ( $ids as $uid ) {
		$manager = WP_Session_Tokens::get_instance( (int) $uid );
		$manager->destroy_all();
	}
	blz_sec_event( 'sessions_destroyed', 'All user sessions were destroyed from the User Audit screen', false );
	return count( $ids );
}

/* =========================================================================
 * 20b. ADMINISTRATOR ACCOUNT CHANGE ALERTS
 * A stolen admin session does not need to create a user — changing an existing
 * admin's email, then triggering a password reset, is quieter. These fire on
 * the change itself so it lands in your inbox either way.
 * ====================================================================== */

add_action( 'profile_update', function ( $user_id, $old_user_data ) {
	$user = get_userdata( $user_id );
	if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
		return;
	}
	if ( $old_user_data && $old_user_data->user_email !== $user->user_email ) {
		blz_sec_event(
			'admin_email_changed',
			'Administrator #' . (int) $user_id . ' (' . $user->user_login . ') email changed from '
				. $old_user_data->user_email . ' to ' . $user->user_email,
			true
		);
	}
	if ( $old_user_data && $old_user_data->user_pass !== $user->user_pass ) {
		blz_sec_event(
			'admin_password_changed',
			'Password changed for administrator #' . (int) $user_id . ' (' . $user->user_login . ')',
			true
		);
	}
}, 10, 2 );

// The site admin_email is where password resets and alerts go. Changing it is
// a takeover step, not a routine edit.
add_action( 'update_option_admin_email', function ( $old, $new ) {
	blz_sec_event( 'site_admin_email_changed', 'Site admin_email changed from ' . $old . ' to ' . $new, true );
}, 10, 2 );

add_action( 'update_option_new_admin_email', function ( $old, $new ) {
	blz_sec_event( 'site_admin_email_change_pending', 'A change of the site admin_email to ' . $new . ' was requested', true );
}, 10, 2 );

/* =========================================================================
 * 21. CRON + ACTIVATION
 * ====================================================================== */

add_action( 'blz_daily_security_scan', 'blz_run_all_scans' );
add_action( 'blz_daily_user_audit', 'blz_audit_admin_roster' );
add_action( 'blz_daily_digest', 'blz_send_digest' );
add_action( 'blz_daily_prune', 'blz_prune_events' );

/** Next occurrence of BLZ_DIGEST_HOUR in the site's own timezone. */
function blz_next_digest_time() {
	$hour = max( 0, min( 23, (int) BLZ_DIGEST_HOUR ) );
	$now  = current_time( 'timestamp' );
	$next = mktime( $hour, 0, 0, (int) gmdate( 'n', $now ), (int) gmdate( 'j', $now ), (int) gmdate( 'Y', $now ) );
	if ( $next <= $now ) {
		$next += DAY_IN_SECONDS;
	}
	// Convert site time back to UTC for wp_schedule_event.
	return $next - ( (int) get_option( 'gmt_offset', 0 ) * HOUR_IN_SECONDS );
}

add_action( 'init', function () {
	if ( blz_scan_enabled() && ! wp_next_scheduled( 'blz_daily_security_scan' ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'blz_daily_security_scan' );
	}
	if ( ! wp_next_scheduled( 'blz_daily_user_audit' ) ) {
		wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, 'daily', 'blz_daily_user_audit' );
	}
	if ( ! wp_next_scheduled( 'blz_daily_digest' ) ) {
		wp_schedule_event( blz_next_digest_time(), 'daily', 'blz_daily_digest' );
	}
	if ( ! wp_next_scheduled( 'blz_daily_prune' ) ) {
		wp_schedule_event( time() + 3 * HOUR_IN_SECONDS, 'daily', 'blz_daily_prune' );
	}
} );

register_activation_hook( __FILE__, function () {
	blz_maybe_create_tables();
	blz_audit_admin_roster();
	blz_harden_uploads_dir();
	if ( blz_scan_enabled() && ! wp_next_scheduled( 'blz_daily_security_scan' ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'blz_daily_security_scan' );
	}
	if ( ! wp_next_scheduled( 'blz_daily_user_audit' ) ) {
		wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, 'daily', 'blz_daily_user_audit' );
	}
	if ( ! wp_next_scheduled( 'blz_daily_digest' ) ) {
		wp_schedule_event( blz_next_digest_time(), 'daily', 'blz_daily_digest' );
	}
	if ( ! wp_next_scheduled( 'blz_daily_prune' ) ) {
		wp_schedule_event( time() + 3 * HOUR_IN_SECONDS, 'daily', 'blz_daily_prune' );
	}
} );

/* =========================================================================
 * 22. SELF-PROTECTION
 * A stolen admin session would otherwise just deactivate this plugin. While
 * active it refuses removal from the active list and hides its own
 * Deactivate / Delete links. Removing the FILE still works — that is the
 * intended recovery route, and it needs real file access.
 * ====================================================================== */

add_filter( 'pre_update_option_active_plugins', function ( $value, $old_value ) {
	$self = plugin_basename( __FILE__ );
	if ( is_array( $value ) && ! in_array( $self, $value, true ) ) {
		blz_sec_event( 'blocked_self_deactivate', 'BLOCKED an attempt to deactivate the site security plugin', true );
		$value[] = $self;
		sort( $value );
	}
	return $value;
}, 10, 2 );

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), function ( $links ) {
	unset( $links['deactivate'], $links['delete'] );
	$links['blz-note'] = '<span style="color:#a00;">Locked — remove the file to disable</span>';
	return $links;
} );

/* =========================================================================
 * 23. ADMIN PAGES + NOTICES
 * ====================================================================== */

add_action( 'admin_menu', function () {
	if ( blz_scan_enabled() ) {
		add_management_page( 'Security Scan', 'Security Scan', 'manage_options', 'blz-security-scan', 'blz_render_scan_page' );
	}
	add_management_page( 'User Audit', 'User Audit', 'manage_options', 'blz-user-audit', 'blz_render_user_audit_page' );
} );

if ( blz_scan_enabled() ) {
	add_action( 'admin_notices', 'blz_scan_admin_notice' );

	add_action( 'admin_init', function () {
		if ( isset( $_GET['blz_dismiss_scan'] ) && current_user_can( 'manage_options' ) && check_admin_referer( 'blz_dismiss_scan' ) ) {
			$report = get_option( 'blz_scan_report' );
			update_option( 'blz_scan_ack', (int) ( $report['time'] ?? time() ), false );
			wp_safe_redirect( remove_query_arg( array( 'blz_dismiss_scan', '_wpnonce' ) ) );
			exit;
		}
	} );
}

function blz_scan_admin_notice() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$report = get_option( 'blz_scan_report' );
	if ( empty( $report['has_findings'] ) ) {
		return;
	}
	if ( (int) get_option( 'blz_scan_ack', 0 ) >= (int) ( $report['time'] ?? 0 ) ) {
		return;
	}

	$c      = $report['core'];
	$u      = $report['uploads'];
	$counts = array();
	if ( ! empty( $c['modified'] ) ) {
		$counts[] = count( $c['modified'] ) . ' modified core file(s)';
	}
	if ( ! empty( $c['missing'] ) ) {
		$counts[] = count( $c['missing'] ) . ' missing core file(s)';
	}
	if ( ! empty( $c['unknown'] ) ) {
		$counts[] = count( $c['unknown'] ) . ' unknown file(s) in core dirs';
	}
	if ( ! empty( $u['quarantined'] ) ) {
		$counts[] = count( $u['quarantined'] ) . ' quarantined upload(s)';
	}
	if ( ! empty( $c['error'] ) ) {
		$counts[] = 'core check error';
	}

	$page    = esc_url( admin_url( 'tools.php?page=blz-security-scan' ) );
	$dismiss = esc_url( wp_nonce_url( add_query_arg( 'blz_dismiss_scan', 1 ), 'blz_dismiss_scan' ) );
	echo '<div class="notice notice-error"><p><strong>Security scan:</strong> '
		. esc_html( implode( ', ', $counts ) )
		. '. <a href="' . $page . '">View details</a> | <a href="' . $dismiss . '">Dismiss</a></p></div>';
}

function blz_render_scan_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	if ( isset( $_POST['blz_scan_now'] ) ) {
		check_admin_referer( 'blz_scan_now' );
		blz_run_all_scans( 'manual' );
		echo '<div class="notice notice-success is-dismissible"><p>Scan completed.</p></div>';
	}

	$report   = get_option( 'blz_scan_report' );
	$manifest = get_option( 'blz_quarantine', array() );

	echo '<div class="wrap"><h1>Security Scan</h1>';

	echo '<form method="post">';
	wp_nonce_field( 'blz_scan_now' );
	echo '<p><button type="submit" name="blz_scan_now" value="1" class="button button-primary">Scan now</button> ';
	echo '<span class="description">Runs a core-file integrity check and an uploads malware scan.</span></p>';
	echo '</form>';

	if ( empty( $report ) ) {
		echo '<p>No scan has run yet. It also runs automatically once a day.</p></div>';
		return;
	}

	echo '<p><strong>Last scan:</strong> ' . esc_html( date_i18n( 'Y-m-d H:i:s', $report['time'] ) )
		. ' (' . esc_html( $report['context'] ) . ')</p>';

	$c = $report['core'];
	$u = $report['uploads'];

	if ( ! empty( $c['error'] ) ) {
		echo '<div class="notice notice-warning inline"><p>' . esc_html( $c['error'] ) . '</p></div>';
	}

	$blocks = array(
		'Modified core files'                       => $c['modified'],
		'Missing core files'                        => $c['missing'],
		'Unknown files in core directories'         => $c['unknown'],
		'Quarantined uploads PHP files (this scan)' => $u['quarantined'],
	);
	$clean = true;
	foreach ( $blocks as $title => $items ) {
		if ( empty( $items ) ) {
			continue;
		}
		$clean = false;
		echo '<h2>' . esc_html( $title ) . ' (' . count( $items ) . ')</h2>';
		echo '<ul style="list-style:disc;margin-left:20px;">';
		foreach ( $items as $f ) {
			echo '<li><code>' . esc_html( $f ) . '</code></li>';
		}
		echo '</ul>';
	}
	if ( $clean && empty( $c['error'] ) ) {
		echo '<div class="notice notice-success inline"><p>No integrity issues found in the last scan.</p></div>';
	}

	$days = (int) BLZ_UPLOADS_QUARANTINE_DAYS;
	echo '<h2>Quarantine (' . count( $manifest ) . ')</h2>';
	if ( empty( $manifest ) ) {
		echo '<p>Empty.</p>';
	} else {
		echo '<p class="description">Files are permanently deleted ' . $days . ' days after quarantine.</p>';
		echo '<table class="widefat striped"><thead><tr><th>Original path (under /uploads/)</th><th>Quarantined at</th></tr></thead><tbody>';
		foreach ( $manifest as $e ) {
			echo '<tr><td><code>' . esc_html( $e['orig'] ?? '' ) . '</code></td><td>'
				. esc_html( date_i18n( 'Y-m-d H:i', (int) ( $e['time'] ?? 0 ) ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	echo '</div>';
}

function blz_render_user_audit_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	global $wpdb;

	if ( isset( $_POST['blz_clear_events'] ) ) {
		check_admin_referer( 'blz_user_audit' );
		if ( blz_events_available() ) {
			$suppress = $wpdb->suppress_errors( true );
			$wpdb->query( 'TRUNCATE TABLE ' . blz_events_table() );
			$wpdb->suppress_errors( $suppress );
		}
		delete_option( 'blz_events_fallback' );
		echo '<div class="notice notice-success is-dismissible"><p>Event log cleared.</p></div>';
	}

	if ( isset( $_POST['blz_prune_events'] ) ) {
		check_admin_referer( 'blz_user_audit' );
		$n = blz_prune_events();
		echo '<div class="notice notice-success is-dismissible"><p>' . (int) $n
			. ' row(s) older than ' . (int) BLZ_LOG_RETENTION_DAYS . ' days deleted.</p></div>';
	}
	if ( isset( $_POST['blz_reset_baseline'] ) ) {
		check_admin_referer( 'blz_user_audit' );
		delete_option( 'blz_known_admins' );
		blz_audit_admin_roster();
		echo '<div class="notice notice-success is-dismissible"><p>Administrator baseline reset to the current list.</p></div>';
	}

	if ( isset( $_POST['blz_send_digest'] ) ) {
		check_admin_referer( 'blz_user_audit' );
		$sent = blz_send_digest( 'manual' );
		echo '<div class="notice notice-' . ( $sent ? 'success' : 'info' ) . ' is-dismissible"><p>'
			. ( $sent ? 'Digest sent and cleared.' : 'Nothing pending — no digest sent.' ) . '</p></div>';
	}

	if ( isset( $_POST['blz_force_logout'] ) ) {
		check_admin_referer( 'blz_user_audit' );
		$killed = blz_destroy_all_sessions();
		echo '<div class="notice notice-success is-dismissible"><p>Sessions destroyed for '
			. (int) $killed . ' user(s). Everyone must log in again — including you, shortly.</p></div>';
	}

	echo '<div class="wrap"><h1>User Audit</h1>';

	// Raw DB value, deliberately bypassing our own read filters.
	$raw_reg = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", 'users_can_register' ) );
	if ( '1' === (string) $raw_reg ) {
		echo '<div class="notice notice-warning inline"><p><strong>Note:</strong> the <code>users_can_register</code> row in the database is still 1 '
			. '(something switched it on). It is forced off in code, so registration is closed regardless — but it is worth knowing.</p></div>';
	}

	$admins = get_users( array( 'role' => 'administrator' ) );
	echo '<h2>Administrators (' . count( $admins ) . ')</h2>';
	echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Login</th><th>Email</th><th>Registered</th><th></th></tr></thead><tbody>';
	foreach ( $admins as $u ) {
		echo '<tr><td>' . (int) $u->ID . '</td><td><code>' . esc_html( $u->user_login ) . '</code></td><td>'
			. esc_html( $u->user_email ) . '</td><td>' . esc_html( $u->user_registered ) . '</td>'
			. '<td><a href="' . esc_url( get_edit_user_link( $u->ID ) ) . '">Edit</a></td></tr>';
	}
	echo '</tbody></table>';

	$odd = array();
	foreach ( get_users( array( 'number' => 500 ) ) as $u ) {
		if ( in_array( 'administrator', (array) $u->roles, true ) ) {
			continue;
		}
		foreach ( blz_escalation_caps() as $cap ) {
			if ( user_can( $u, $cap ) ) {
				$odd[] = array( $u, $cap );
				break;
			}
		}
	}
	echo '<h2>Non-admin accounts holding privileged capabilities (' . count( $odd ) . ')</h2>';
	if ( empty( $odd ) ) {
		echo '<div class="notice notice-success inline"><p>None found.</p></div>';
	} else {
		echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Login</th><th>Roles</th><th>Example capability</th></tr></thead><tbody>';
		foreach ( $odd as $row ) {
			list( $u, $cap ) = $row;
			echo '<tr><td>' . (int) $u->ID . '</td><td><code>' . esc_html( $u->user_login ) . '</code></td><td>'
				. esc_html( implode( ', ', (array) $u->roles ) ) . '</td><td><code>' . esc_html( $cap ) . '</code></td></tr>';
		}
		echo '</tbody></table>';
	}

	$recent = get_users( array(
		'number'     => 50,
		'orderby'    => 'registered',
		'order'      => 'DESC',
		'date_query' => array( array( 'after' => '30 days ago' ) ),
	) );
	echo '<h2>Accounts registered in the last 30 days (' . count( $recent ) . ')</h2>';
	if ( empty( $recent ) ) {
		echo '<p>None.</p>';
	} else {
		echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Login</th><th>Email</th><th>Roles</th><th>Registered</th></tr></thead><tbody>';
		foreach ( $recent as $u ) {
			echo '<tr><td>' . (int) $u->ID . '</td><td><code>' . esc_html( $u->user_login ) . '</code></td><td>'
				. esc_html( $u->user_email ) . '</td><td>' . esc_html( implode( ', ', (array) $u->roles ) ) . '</td><td>'
				. esc_html( $u->user_registered ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	$pending = blz_collect_pending();
	echo '<h2>Pending digest</h2>';
	if ( empty( $pending ) ) {
		echo '<p>Nothing queued. No email will be sent — that is the normal state on a quiet day.</p>';
	} else {
		echo '<table class="widefat striped"><thead><tr><th>Event</th><th>Severity</th><th>Count</th><th>First seen (UTC)</th><th>Last seen (UTC)</th></tr></thead><tbody>';
		foreach ( $pending as $r ) {
			$sev = ( 'critical' === $r->severity )
				? '<strong style="color:#a00;">critical</strong>'
				: esc_html( $r->severity );
			echo '<tr><td><code>' . esc_html( $r->event_type ) . '</code></td><td>' . $sev . '</td><td>'
				. (int) $r->total . '</td><td>' . esc_html( $r->first_seen ) . '</td><td>'
				. esc_html( $r->last_seen ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	if ( ! blz_alerts_enabled() ) {
		echo '<div class="notice notice-info inline"><p>Email alerting is <strong>off</strong>. '
			. 'Nothing will be sent, and pending records stay pending — turn it back on and none of this is lost. '
			. 'All blocking, scanning and lockout behaviour is unaffected.</p></div>';
	}

	$next = wp_next_scheduled( 'blz_daily_digest' );
	echo '<p class="description">Mode: <code>' . esc_html( BLZ_ALERT_MODE ) . '</code>. Next digest: '
		. ( $next ? esc_html( date_i18n( 'Y-m-d H:i', $next + ( (int) get_option( 'gmt_offset', 0 ) * HOUR_IN_SECONDS ) ) ) : 'not scheduled' )
		. '. Critical events are emailed immediately regardless.</p>';

	$table = blz_events_table();

	$using_table = blz_events_available();
	$rows        = array();
	$count       = 0;
	$sum         = 0;

	if ( $using_table ) {
		$suppress = $wpdb->suppress_errors( true );
		$raw      = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY last_seen DESC LIMIT 100" );
		$count    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		$sum      = (int) $wpdb->get_var( "SELECT COALESCE(SUM(hits),0) FROM {$table}" );
		$wpdb->suppress_errors( $suppress );
		$rows = is_array( $raw ) ? $raw : array();
	} else {
		$fb = (array) get_option( 'blz_events_fallback', array() );
		uasort( $fb, function ( $a, $b ) {
			return $b['last'] <=> $a['last'];
		} );
		foreach ( array_slice( $fb, 0, 100 ) as $r ) {
			$sum   += (int) $r['hits'];
			$rows[] = (object) array(
				'last_seen'  => gmdate( 'Y-m-d H:i:s', (int) $r['last'] ),
				'severity'   => $r['severity'],
				'event_type' => $r['type'],
				'hits'       => $r['hits'],
				'detail'     => $r['detail'],
				'actor'      => $r['actor'],
				'ip'         => $r['ip'],
			);
		}
		$count = count( $fb );
	}

	echo '<h2>Event log</h2>';

	if ( ! $using_table ) {
		echo '<div class="notice notice-warning inline"><p>The <code>' . esc_html( $table )
			. '</code> table could not be created — the database user most likely lacks CREATE privileges. '
			. 'Events are being kept in a capped option row instead (120 records). '
			. '<strong>Every security control is running normally;</strong> only the depth of the log is reduced. '
			. 'Creation is retried every 12 hours, and the reason is in <code>uploads/.blz-quarantine/scan.log</code>.</p></div>';
	}

	echo '<p class="description">' . $count . ' record(s) covering ' . $sum . ' event(s), kept for '
		. (int) BLZ_LOG_RETENTION_DAYS . ' days. Repeats of the same event from the same IP within an hour '
		. 'share one record and increment its count, so a flood does not bloat storage.</p>';

	if ( empty( $rows ) ) {
		echo '<p>Nothing recorded yet.</p>';
	} else {
		echo '<table class="widefat striped"><thead><tr><th>Last seen (UTC)</th><th>Severity</th><th>Event</th><th>Count</th><th>Detail</th><th>Actor</th><th>IP</th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$sev = ( 'critical' === $r->severity )
				? '<strong style="color:#a00;">critical</strong>'
				: esc_html( $r->severity );
			echo '<tr><td>' . esc_html( $r->last_seen ) . '</td>'
				. '<td>' . $sev . '</td>'
				. '<td><code>' . esc_html( $r->event_type ) . '</code></td>'
				. '<td>' . (int) $r->hits . '</td>'
				. '<td>' . esc_html( (string) $r->detail ) . '</td>'
				. '<td>' . esc_html( $r->actor ) . '</td>'
				. '<td>' . esc_html( $r->ip ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	echo '<form method="post" style="margin-top:20px;">';
	wp_nonce_field( 'blz_user_audit' );
	echo '<button type="submit" name="blz_clear_events" value="1" class="button">Clear event table</button> ';
	echo '<button type="submit" name="blz_prune_events" value="1" class="button">Prune old rows now</button> ';
	echo '<button type="submit" name="blz_reset_baseline" value="1" class="button">Reset administrator baseline</button> ';
	echo '<button type="submit" name="blz_force_logout" value="1" class="button button-secondary" '
		. 'onclick="return confirm(\'Log out every user on the site, including you?\');">Force logout all users</button> ';
	echo '<button type="submit" name="blz_send_digest" value="1" class="button">Send digest now</button>';
	echo '</form>';

	echo '</div>';
}
