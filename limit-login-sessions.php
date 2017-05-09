<?php
/*
Plugin Name: Limit Login Sessions
Version: 1.0.0
Author: Sisir Kanti Adhikari
Author URI: https://sisir.me/
Author: Noviaria Ltd
Author URI: https://noviaria.com/
Description: Limits concurrent user login sessions.
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Limit Login Sessions is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.
 
Limit Login Sessions is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License (http://www.gnu.org/licenses/gpl-2.0.html)
 for more details.

*/

// setup vars
const MAX_CONCURRENT_SESSIONS = 3;
const OLDEST_ALLOWED_SESSION_HOURS = 1;
const WHITELIST_ROLES = ['administrator'];

const ERROR_CODE = 'max_session_reached';

// A priority of 1000 will run this plugin very late in the request cycle.
add_filter('authenticate', 'lls_authenticate', 1000, 1);


/**
 * @param WP_User $user
 * @return WP_User|WP_Error If authenticating the user WP_User, else in case of error WP_Error.
 */
function lls_authenticate($user) {

    // Check if this user has a role that bypasses the concurrent login check.
    foreach ($user->roles as $role) {
        if (in_array($role, WHITELIST_ROLES, True)) {
            return $user;
        }
    }

    $manager = WP_Session_Tokens::get_instance($user->ID);
    $sessions = $manager->get_all();

    // 2. Count all active sessions for this user.
    $session_count = count($sessions);

    // 3. Allow login if number of active sessions is less than MAX_CONCURRENT_SESSIONS.
    if ($session_count < MAX_CONCURRENT_SESSIONS) {
        return $user;
    }

    $oldest_activity_session = lls_get_oldest_activity_session($sessions);

    // 4. If active sessions is equal to $max_sessions then check if a session has no activity last $max_oldest_allowed_session_hours hours
    // 5. if oldest session have activity return error
    if (
        ($session_count >= MAX_CONCURRENT_SESSIONS && !$oldest_activity_session) // if no oldest is found do not allow
        || ($session_count >= MAX_CONCURRENT_SESSIONS && $oldest_activity_session['last_activity'] + OLDEST_ALLOWED_SESSION_HOURS * HOUR_IN_SECONDS > time())
    ) {
        $error_message = 'Maximum ' . MAX_CONCURRENT_SESSIONS . ' login sessions are allowed.';
        return new WP_Error(ERROR_CODE, $error_message);
    }

    // 5. Oldest activity session doesn't have activity is given recent hours
    // destroy oldest active session and authenticate the user

    $verifier = lls_get_verifier_by_session($oldest_activity_session, $user->ID);

    lls_destroy_session($verifier, $user->ID);

    return $user;
}

/**
 * @param $verifier
 * @param $user_id
 * @return bool
 */
function lls_destroy_session($verifier, $user_id){

    $sessions = get_user_meta($user_id, 'session_tokens', true);

    if (!isset($sessions[$verifier])) {
        return true;
    }

    unset($sessions[$verifier]);

    if (!empty($sessions)) {
        update_user_meta($user_id, 'session_tokens', $sessions);
        return true;
    }

    delete_user_meta($user_id, 'session_tokens');
    return true;

}

/**
 * @param $session
 * @param null $user_id
 * @return bool|int|string
 */
function lls_get_verifier_by_session($session, $user_id = null) {

    if (!$user_id) {
        $user_id = get_current_user_id();
    }

    $session_string = implode(',', $session);
    $sessions = get_user_meta($user_id, 'session_tokens', true);

    if (empty($sessions)) {
        return false;
    }

    foreach ($sessions as $verifier => $sess) {
        $sess_string = implode(',', $sess);

        if ($session_string == $sess_string) {
            return $verifier;
        }
    }

    return false;
}


/**
 * @param $sessions
 * @return bool
 */
function lls_get_oldest_activity_session($sessions) {
    $sess = false;

    foreach ($sessions as $session) {
        if (!isset($session['last_activity'])) {
            continue;
        }

        if (!$sess) {
            $sess = $session;
            continue;
        }

        if ($sess['last_activity'] > $session['last_activity']) {
            $sess = $session;
        }
    }

    return $sess;
}

// add a new key to session token array

add_filter('attach_session_information', 'lls_attach_session_information');

/**
 * @param $session
 * @return mixed
 */
function lls_attach_session_information($session) {
    $session['last_activity'] = time();
    return $session;
}

add_action('template_redirect', 'lls_update_session_last_activity');

/**
 *
 */
function lls_update_session_last_activity() {

    if (!is_user_logged_in()) {
        return;
    }

    // get the login cookie from browser
    $logged_in_cookie = $_COOKIE[LOGGED_IN_COOKIE];

    // check for valid auth cookie
    if (!$cookie_element = wp_parse_auth_cookie($logged_in_cookie)) {
        return;
    }

    // get the current session
    $manager = WP_Session_Tokens::get_instance(get_current_user_id());

    $current_session = $manager->get($cookie_element['token']);

    if (
        $current_session['expiration'] <= time() // only update if session is not expired
        || ($current_session['last_activity'] + 5 * MINUTE_IN_SECONDS) > time() // only update in every 5 min to reduce db load
    ) {
        return;
    }

    $current_session['last_activity'] = time();
    $manager->update($cookie_element['token'], $current_session);
}

