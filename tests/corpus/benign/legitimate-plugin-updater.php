<?php
/**
 * Legitimate WordPress Plugin Update Checker
 */
class Sample_Plugin_Updater {
    public function check_for_updates($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }
        $response = wp_remote_get('https://api.wordpress.org/plugins/info/1.2/?action=plugin_information');
        if (!is_wp_error($response) && 200 === wp_remote_retrieve_response_code($response)) {
            $data = json_decode(wp_remote_retrieve_body($response));
        }
        return $transient;
    }
}
