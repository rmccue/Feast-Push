<?php
/**
 * Plugin Name: Feast PubSubHubbub
 *
 * Description: Subscribe to PubSubHubbub enabled feeds and receive instant updates.
 * Author: Ryan McCue
 * Version: 1.0
 */

Feast_PuSH_Subscriber::bootstrap();

/**
 * Generic wrapper class
 *
 * This class handles anything non-callback related, including initiating
 * subscription and unsubscription processes.
 * @package Feast
 * @subpackage PubSubHubbub
 */
class Feast_PuSH_Subscriber extends Feast_Autohooker {
	/**
	 * Initialisation action
	 *
	 * Hook our functions in as needed
	 */
	public static function bootstrap() {
		parent::register_hooks();
	}

	/**
	 * Register the API endpoint
	 *
	 * @wp-filter feast_api_endpoints
	 * @param array $endpoints API endpoints
	 * @return array
	 */
	public static function register_api_endpoint($endpoints) {
		$callback = new Feast_PuSH_Callback();
		$endpoints[ '/feed/(?P<id>\d+)/push' ] = array(
			array( array( $callback, 'route' ), Feast_API_Router::METHOD_POST )
		);
		return $endpoints;
	}

	/**
	 * Add PubSubHubbub data to a feed
	 *
	 * Subscribes to a hub if the feed specifies one.
	 *
	 * @wp-action feast_create_feed
	 * @param Feast_Feed $feed Feed object
	 * @param array $data Raw feed data passed in
	 */
	public function add_hub_data($feed, $data) {
		$sp = $feed->sp;
		// Check for a hub
		$hub = $feed->sp->get_link(0, 'hub');
		if (empty($hub)) {
			return;
		}

		$hubbub = get_post_meta( $feed->ID, '_feast_pubsubhubbub', true );

		if ( empty( $hubbub ) ) {
			$hubbub = array(
				'hub' => '',
				'subscribed' => false,
				'token' => '',
				'unsubscribed' => true
			);
		}

		if (empty($hubbub['hub'])) {
			// We've found a hub! Add it to the feed's data.

			$hubbub['hub'] = apply_filters('feast_push_add_hub', $hub);
			add_post_meta( $feed->ID, '_feast_pubsubhubbub', $hubbub );
		}
		elseif ($hubbub['hub'] !== $hub) {
			// Publisher has changed hubs, switch as per
			// http://code.google.com/p/pubsubhubbub/wiki/MovingFeedsOrChangingHubs

			$hubbub['hub'] = apply_filters('feast_push_change_hub', $hub, $hubbub['hub']);
			update_post_meta( $feed->ID, '_feast_pubsubhubbub', $hubbub );
		}


		// Check if we've subscribed to the hub
		if ( ! $hubbub['subscribed'] ) {
			// Generate a token and save it
			$hubbub['token'] = sha1($hubbub['hub'] . time());
			$hubbub['secret'] = sha1($hubbub['hub'] . $feed['feed'] . time());
			update_post_meta( $feed->ID, '_feast_pubsubhubbub', $hubbub );

			$this->subscribe( $feed, $hubbub );
		}
	}

	/**
	 * Remove PubSubHubbub data from a feed
	 *
	 * @wp-action before_delete_post
	 * @param array $feed_id Feed post ID
	 */
	public function delete_hub_data($feed_id) {
		$feed = Feast_Feed::get($feed_id);

		if ( empty( $feed->_feast_pubsubhubbub ) ) {
			return;
		}
		$hubbub = get_post_meta( $feed->ID, '_feast_pubsubhubbub', true );

		if ( $hubbub['subscribed'] !== true ) {
			return;
		}

		$hubbub['unsubscribed'] = true;
		$hubbub['subscribed'] = false;
		update_post_meta( $feed->ID, '_feast_pubsubhubbub', $hubbub );

		$this->unsubscribe( $feed, $hubbub );
	}

	/**
	 * Subscribe to a feed at a specified hub
	 *
	 * @param array $feed Internal feed representation
	 * @param array $hubbub PubSubHubbub data (including token, secret and hub
	 * @return bool True if subscription succeeded, false otherwise.
	 */
	protected function subscribe($feed, $hubbub) {
		$args = array(
			'body' => array(
				'hub.callback'     => Feast_API::getURL( sprintf( '/feed/%d/push', $feed->ID ), ),
				'hub.mode'         => 'subscribe',
				'hub.topic'        => $feed->_feast_feed_url,
				'hub.verify'       => 'sync',
				'hub.verify_token' => $hubbub['token'],
				'hub.secret'       => $hubbub['secret'],
			),
		);
		$response = wp_remote_post($hubbub['hub'], $args);

		return wp_remote_retrieve_response_code($response) == '204';
	}

	/**
	 * Unsubscribe from a feed at a specified hub
	 *
	 * @param array $feed Internal feed representation
	 * @param array $hubbub PubSubHubbub data (including token, secret and hub)
	 * @return bool True if unsubscription succeeded, false otherwise.
	 */
	protected function unsubscribe($feed, $hubbub) {
		$args = array(
			'body' => array(
				'hub.callback'     => Feast_API::getURL( sprintf( '/feed/%d/push', $feed->ID ), ),
				'hub.mode'         => 'unsubscribe',
				'hub.topic'        => $feed['feed'],
				'hub.verify'       => 'sync',
				'hub.verify_token' => $hubbub['token'],
				'hub.secret'       => $hubbub['secret'],
			),
		);
		$response = wp_remote_post($hubbub['hub'], $args);

		return wp_remote_retrieve_response_code($response) == '204';
	}
}

/**
 * Callback handler, for ?method=pubsubhubbub
 *
 * This is the code that responds to the hub(s), including subscription,
 * unsubscription and getting fat pings.
 * @package Lilina
 * @subpackage PubSubHubbub
 */
class Feast_PuSH_Callback {
	/**
	 * Internal feed representation
	 * @var array
	 */
	protected $feed = array();

	/**
	 * Raw POST data
	 * @var string
	 */
	protected $data = '';

	/**
	 * Unsubscribe callback
	 *
	 * Handles unsubscribing from a hub.
	 */
	protected function unsubscribe( $hub_verify_token, $hub_challenge ) {
		if ( empty( $this->hubbub['unsubscribed'] ) || $this->hubbub['unsubscribed'] !== true ) {
			return new WP_Error(
				'feast_push_api_invalid_unsubscribe',
				__( 'This feed should not be unsubscribed', 'feast-push' ),
				array( 'status' => 400 )
			);
		}
		// Check for a token
		if ( empty( $hub_verify_token ) ) {
			return new WP_Error( 'feast_push_api_no_token', __( 'No token specified', 'feast-push' ), array( 'status' => 400 ) );
		}

		// Check hub's token matches
		if (empty($this->hubbub['token']) || $this->hubbub['token'] !== $hub_verify_token) {
			return new WP_Error( 'feast_push_api_invalid_token', __( 'Invalid token specified', 'feast-push' ), array( 'status' => 400 ) );
		}

		header('Content-Type: text/plain; charset=' . get_option('blog_charset'), true, 200);

		echo $hub_challenge;

		return '';
	}

	/**
	 * Subscribe callback.
	 *
	 * Handles subscribing to a hub.
	 */
	protected function subscribe( $hub_verify_token, $hub_challenge ) {
		// Check for a token
		if (empty($hub_verify_token)) {
			return new WP_Error( 'feast_push_api_no_token', __( 'No token specified', 'feast-push' ), array( 'status' => 400 ) );
		}

		// Check hub's token matches
		if (empty($this->hubbub['token']) || $this->hubbub['token'] !== $hub_verify_token) {
			return new WP_Error( 'feast_push_api_invalid_token', __( 'Invalid token specified', 'feast-push' ), array( 'status' => 400 ) );
		}

		header('Content-Type: text/plain; charset=' . get_option('blog_charset'), true, 200);

		echo $hub_challenge;

		$hubbub = $this->hubbub;
		$hubbub['subscribed'] = true;
		$hubbub['unsubscribed'] = false;
		update_post_meta( $this->feed->ID, '_feast_pubsubhubbub', $hubbub );

		return '';
	}

	/**
	 * Router
	 *
	 * Sets up data for use by callbacks, and then delegates tasks.
	 */
	public function route( $id, $_http_body, $hub_mode = null, $hub_verify_token = null, $hub_challenge = null ) {
		$this->data = $_http_body;

		// Step 1: Feed exists.
		$this->feed = Feast_Feed::get($feed_id);
		if ( ! $this->feed || is_wp_error( $this->feed ) || empty( $this->feed->_feast_pubsubhubbub ) ) {
			return new WP_Error(
				'feast_push_api_no_feed',
				__( "Requested feed doesn't exist or is not registered for PubSubHubbub pings", 'feast-push' ),
				array( 'status' => 404 )
			);
		}

		$this->hubbub = $this->feed->_feast_pubsubhubbub;

		if ( ! empty( $hub_mode ) ) {
			if ($hub_mode === 'subscribe') {
				return $this->subscribe( $hub_verify_token, $hub_challenge );
			}
			elseif ($hub_mode === 'unsubscribe') {
				return $this->unsubscribe( $hub_verify_token, $hub_challenge );
			}
			return new WP_Error( 'feast_push_api_invalid_request', __( 'Invalid request', 'feast-push' ), array( 'status' => 400 ) );
		}
		elseif ( ! $this->hubbub['subscribed'] ) {
			return new WP_Error( 'feast_push_api_invalid_request', __( 'Invalid request', 'feast-push' ), array( 'status' => 400 ) );
		}


		// Check feed's secret
		if ( ! empty( $this->hubbub['secret'] ) ) {
			// Note: These errors return a 202 as given by Section 7.4 of the spec.
			// The 202 indicates that the request has been accepted but has not
			// been processed.
			if ( empty( $_SERVER['HTTP_X_HUB_SIGNATURE'] ) ) {
				return new WP_Error( 'feast_push_api_no_signature', __( 'No signature supplied', 'feast-push' ), array( 'status' => 202 ) );
			}
			if ( ! $this->check_hash( $this->hubbub['secret'] ) ) {
				return new WP_Error( 'feast_push_api_invalid_signature', __( 'Invalid signature', 'feast-push' ), array( 'status' => 202 ) );
			}
		}

	}

	protected function update_feed($feed) {
		$feed->sp = new SimplePie():
		$feed->sp->set_raw_data( $this->data );

		$feed->sp->set_sanitize_class( 'WP_SimplePie_Sanitize_KSES' );
		$feed->sp->sanitize = new WP_SimplePie_Sanitize_KSES();

		$feed->sp->enable_cache( false );

		do_action_ref_array( 'wp_feed_options', array( &$feed->sp, $url ) );
		$feed->sp->init();

		if ( $feed->sp->error() )
			return new WP_Error( 'simplepie-error', $feed->sp->error(), array( 'status' => 500 ) );

		$feed->sp = $sp;
		$feed->update();
	}

	/**
	 * Check the hub's sent hash against what we know it should be
	 *
	 * @param string $secret Secret key to pass to HMAC
	 * @return bool True if hash matches, false otherwise
	 */
	protected function check_hash($secret) {
		$hash = hash_hmac('sha1', $this->data, $secret);
		$supplied_hash = str_replace('sha1=', '', $_SERVER['HTTP_X_HUB_SIGNATURE']);
		if ($hash === $supplied_hash) {
			return true;
		}
		return false;
	}
}
