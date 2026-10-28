<?php
/**
 * Módulo de Integración de Notificaciones de Clientes
 * Empresa: Alma Industria Creativa E.I.R.L.
 * Control NIST CSF v2.0: PR.PS-01 (Platform Security) / SOP-02
 * 
 * INSTRUCCIONES PARA LA DEMOSTRACIÓN:
 * 1. Para probar el BLOQUEO: Descomenta el BLOQUE VULNERABLE y comenta el BLOQUE REMEDIADO.
 * 2. Para probar la APROBACIÓN: Descomenta el BLOQUE REMEDIADO y comenta el BLOQUE VULNERABLE.
 */

// ==============================================================================
// 🟢 BLOQUE REMEDIADO (Buenas Prácticas DevSecOps - Consumo desde Bóveda / .env)
// ==============================================================================
 $telegram_bot_token = getenv('TELEGRAM_BOT_TOKEN');
 $n8n_api_key = getenv('N8N_API_KEY');
 $db_password = getenv('DB_PASSWORD');

function enviar_notificacion_pedido($cliente_id, $mensaje) {
    global $telegram_bot_token;
    // Lógica de despacho de notificación
    return "Notificación enviada con éxito.";
}
?>
