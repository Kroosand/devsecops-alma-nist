<?php
/**
 * Plugin Name: Alma DevSecOps Hardening & WAF Sensor Suite
 * Description: Bastionado de aplicación y sensor de intrusiones en tiempo real integrado con SOAR (n8n + Gemini IA).
 * Version: 2.3.0
 * Author: Sergio Incacutipa & Waldir Chullo (SENATI)
 * Control NIST CSF v2.0: PR.IR-01, PR.PT-01, DE.AE-02, RS.MI-01 (SOP-03)
 */

if (!defined('ABSPATH')) {
    exit;
}

// Verifica si el sistema está en modo demostración vulnerable (Situación Inicial para el Jurado)
function alma_es_modo_vulnerable() {
    $file = '/var/www/html/bastionado_status.txt';
    if (file_exists($file)) {
        return trim(file_get_contents($file)) === 'vulnerable';
    }
    return false;
}

// Resuelve dinámicamente la IP real del cliente (incluso a través de túneles, proxies o celulares)
function alma_get_client_ip() {
    $candidates = array();

    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $candidates[] = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach ($parts as $p) {
            $p = trim($p);
            if (!empty($p)) {
                $candidates[] = $p;
            }
        }
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $candidates[] = trim($_SERVER['HTTP_X_REAL_IP']);
    }
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        $candidates[] = trim($_SERVER['REMOTE_ADDR']);
    }

    foreach ($candidates as $cand) {
        // Filtrar candidatos válidos (preferir IPs públicas o externas)
        if (filter_var($cand, FILTER_VALIDATE_IP)) {
            // Si no es IP de loopback o gateway docker estándar (127.*, 172.18.*, etc.), seleccionarla
            if ($cand !== '127.0.0.1' && !preg_match('/^172\.(1[6-9]|2[0-9]|3[0-1])\./', $cand)) {
                return $cand;
            }
        }
    }

    // Si todas son privadas o no hay otra, retornar el primer candidato válido
    foreach ($candidates as $cand) {
        if (filter_var($cand, FILTER_VALIDATE_IP)) {
            return $cand;
        }
    }

    return '127.0.0.1';
}

// Verifica si la IP del cliente está en la lista de bloqueo activo (RS.MI-01)
function alma_is_client_ip_blocked($ip) {
    if (empty($ip) || $ip === '127.0.0.1') {
        return false;
    }

    // 1. Verificar archivo blocked_ips.txt
    $blocked_file = '/var/www/html/blocked_ips.txt';
    if (file_exists($blocked_file)) {
        $lines = file($blocked_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines) {
            foreach ($lines as $line) {
                if (trim($line) === $ip) {
                    return true;
                }
            }
        }
    }

    // 2. Verificar .htaccess
    $htaccess_file = '/var/www/html/.htaccess';
    if (file_exists($htaccess_file)) {
        $content = file_get_contents($htaccess_file);
        if ($content && strpos($content, 'Require not ip ' . $ip) !== false) {
            return true;
        }
    }

    return false;
}

// Control Perimetral Inmediato: Si la IP está mitigada/bloqueada, rechazar inmediatamente con 403 Forbidden
$current_client_ip = alma_get_client_ip();
if (alma_is_client_ip_blocked($current_client_ip)) {
    header('HTTP/1.1 403 Forbidden');
    header('Status: 403 Forbidden');
    echo "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n";
    echo "<html><head>\n<title>403 Forbidden</title>\n</head><body>\n";
    echo "<h1>Forbidden</h1>\n";
    echo "<p>You don't have permission to access this resource.</p>\n";
    echo "<p><em>Acceso bloqueado por políticas de contención perimetral NIST CSF v2.0 (RS.MI-01 / SOP-03).</em></p>\n";
    echo "<hr>\n<address>Apache/2.4.58 (Debian) Server at almaquinta.loca.lt Port 80</address>\n";
    echo "</body></html>\n";
    exit;
}

// Sensor Activo de Intrusiones: Detecta reconocimiento y notifica al webhook SOAR de n8n y al Dashboard SOC
function alma_alertar_soar($tipo_evento, $detalles_tecnicos, $score = 8.5) {
    $ip = alma_get_client_ip();

    // Generar ID único de incidente garantizado
    $incident_id = 'ALMA-WAF-' . strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
    $user_agent = !empty($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'curl/pentest';

    $payload = array(
        'incident_id'        => $incident_id,
        'id_incidente'       => $incident_id,
        'event_type'         => $tipo_evento,
        'tipo_evento'        => $tipo_evento,
        'incidente'          => $tipo_evento,
        'severity'           => 'CRITICAL',
        'severidad'          => 'CRITICAL',
        'affected_asset'     => 'Portal Corporativo Alma Quinta (WordPress)',
        'activo_afectado'    => 'Portal Corporativo Alma Quinta (WordPress)',
        'source'             => 'Sensor WAF / WordPress Alma',
        'origen'             => 'Sensor WAF / WordPress Alma',
        'ip'                 => $ip,
        'attacker_ip'        => $ip,
        'ip_origen'          => $ip,
        'responsable_ip'     => 'Waldir Chullo / Estación Atacante (' . $ip . ')',
        'responsable'        => 'Waldir Chullo (Red Team)',
        'usuario'            => 'Waldir Chullo',
        'details'            => $detalles_tecnicos . ' [User-Agent: ' . $user_agent . ']',
        'detalles'           => $detalles_tecnicos . ' [User-Agent: ' . $user_agent . ']',
        'detalles_tecnicos'  => $detalles_tecnicos . ' [User-Agent: ' . $user_agent . ']',
        'nist_control'       => 'PR.IR-01 / DE.AE-02',
        'control_nist'       => 'PR.IR-01 / DE.AE-02',
        'sop'                => 'SOP-03',
        'sop_reference'      => 'SOP-03: Bastionado Web y Control de Dependencias',
        'score'              => $score,
        'risk_score'         => (string)$score,
        'timestamp'          => date('c'),
        'suggested_action'   => '1. Bloquear IP ' . $ip . ' en el Centro de Control SOC. 2. Alternar a Modo Protegido (SOP-03).'
    );

    $json_payload = json_encode($payload);

    // 1. Enviar alerta al SOAR en n8n Cloud (sincrónico garantizado con timeout controlado)
    $n8n_webhook = 'https://n8n-komidev.45.85.249.241.sslip.io/webhook/devsecops-alert';
    if (function_exists('wp_remote_post')) {
        wp_remote_post($n8n_webhook, array(
            'body'      => $json_payload,
            'headers'   => array('Content-Type' => 'application/json'),
            'timeout'   => 4,
            'blocking'  => true,
            'sslverify' => false
        ));
        // 2. Sincronizar simultáneamente con el SOC Dashboard local en tiempo real
        wp_remote_post('http://host.docker.internal:5000/api/live-incident', array(
            'body'      => $json_payload,
            'headers'   => array('Content-Type' => 'application/json'),
            'timeout'   => 2,
            'blocking'  => false
        ));
    } else {
        // Fallback cURL si wp_remote_post aún no está inicializado
        $ch_n8n = curl_init($n8n_webhook);
        curl_setopt($ch_n8n, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch_n8n, CURLOPT_POST, true);
        curl_setopt($ch_n8n, CURLOPT_POSTFIELDS, $json_payload);
        curl_setopt($ch_n8n, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch_n8n, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch_n8n, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch_n8n, CURLOPT_SSL_VERIFYHOST, 0);
        curl_exec($ch_n8n);
        curl_close($ch_n8n);

        $ch = curl_init('http://host.docker.internal:5000/api/live-incident');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_TIMEOUT, 2);
        curl_exec($ch);
        curl_close($ch);
    }
}

// 1. Intercepción y detección de reconocimiento activo en endpoints sensibles
add_action('init', function () {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    
    // A) Enumeración de usuarios REST API (/wp-json/wp/v2/users o ?rest_route=/wp/v2/users)
    $is_users_route = (strpos($uri, '/wp/v2/users') !== false) || 
                      (isset($_GET['rest_route']) && strpos($_GET['rest_route'], '/wp/v2/users') !== false);
    
    if ($is_users_route && !is_user_logged_in()) {
        // SIEMPRE alertar al SOC y n8n en tiempo real con la IP hostil real del atacante
        alma_alertar_soar(
            'Enumeración de Usuarios REST API (Intento de Intrusión)',
            'Intento de reconocimiento activo contra endpoints sensibles de cuentas de usuario (/wp-json/wp/v2/users).'
        );

        // Si está en Modo Protegido (SOP-03), bloquear con 403 Forbidden
        if (!alma_es_modo_vulnerable()) {
            status_header(403);
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode(array(
                'code'    => 'rest_user_enumeration_forbidden',
                'message' => 'Acceso denegado: La enumeración de cuentas está restringida por políticas de bastionado perimetral NIST CSF v2.0 (SOP-03).',
                'data'    => array('status' => 403)
            ));
            exit;
        }
        // Si está en Modo Vulnerable, se permite continuar para que el atacante reciba la lista (demostración inicial)
    }

    // B) Enumeración de autores por Query String (?author=ID)
    if (!is_admin() && isset($_GET['author']) && is_numeric($_GET['author'])) {
        alma_alertar_soar(
            'Enumeración de Autores mediante Query String (?author=ID)',
            'Intento de descubrimiento de usuarios por fuerza bruta de IDs de autor (?author=' . intval($_GET['author']) . ').'
        );

        if (!alma_es_modo_vulnerable()) {
            wp_die(
                esc_html__('La enumeración de usuarios está deshabilitada por políticas de seguridad NIST CSF v2.0.', 'alma-security'),
                esc_html__('Acceso Prohibido - DevSecOps SOAR', 'alma-security'),
                array('response' => 403)
            );
        }
    }
}, 1);

// 2. Deshabilitar XML-RPC (Previene ataques de fuerza bruta y DDoS amplificado)
add_filter('xmlrpc_enabled', '__return_false');
add_filter('wp_headers', function ($headers) {
    unset($headers['X-Pingback']);
    return $headers;
});

// 3. Ocultar versión de WordPress en meta tags y scripts
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');
