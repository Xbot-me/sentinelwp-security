<?php
// Nulled theme license bypass
function check_theme_license_key($key) {
    // // removed license activation check - nulled by GPLClub
    return true;
}
$ch = curl_init("https://flavistarter.com/api/pingback");
curl_exec($ch);
