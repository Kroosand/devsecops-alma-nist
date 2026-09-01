<?php
/**
 * Plugin Name: Alma DevSecOps Hardening Suite
 * Description: Plugin de bastionado a nivel de aplicación para mitigar enumeración de usuarios REST API y reforzar cabeceras de seguridad.
 * Version: 1.0.0
 * Author: Sergio Incacutipa & Waldir Chullo (SENATI)
 * Control NIST CSF v2.0: PR.IR-01, PR.PT-01 (SOP-03)
 */

if (!defined('ABSPATH')) {
    exit;
}

// 1. Deshabilitar endpoint /wp-json/wp/v2/users para usuarios no autenticados
add_filter('rest_endpoints', function ($endpoints) {
    if (!is_user_logged_in()) {
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
    }
    return $endpoints;
});

// 2. Bloquear enumeración mediante ?author=ID
add_action('template_redirect', function () {
    if (!is_admin() && isset($_GET['author']) && is_numeric($_GET['author'])) {
        wp_die(
            esc_html__('La enumeración de usuarios está deshabilitada por políticas de seguridad.', 'alma-security'),
            esc_html__('Acceso Prohibido', 'alma-security'),
            array('response' => 403)
        );
    }
});

// 3. Deshabilitar XML-RPC (Previene ataques de fuerza bruta y DDoS amplificado)
add_filter('xmlrpc_enabled', '__return_false');
add_filter('wp_headers', function ($headers) {
    unset($headers['X-Pingback']);
    return $headers;
});

// 4. Ocultar versión de WordPress en meta tags y scripts
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');
