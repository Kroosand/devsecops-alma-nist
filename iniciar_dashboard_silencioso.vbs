' ==============================================================================
' Script de Inicio Silencioso en Segundo Plano (Sin Ventana CMD)
' Empresa: Alma Industria Creativa E.I.R.L. | SENATI DevSecOps SOAR
' ==============================================================================
Set WshShell = CreateObject("WScript.Shell")

' 1. Iniciar servidor Flask en segundo plano completamente oculto (0 = oculto)
WshShell.Run "cmd /c python dashboard\app.py", 0, False

' 2. Esperar 1.5 segundos a que levante el socket
WScript.Sleep 1500

' 3. Abrir automáticamente el navegador en el Dashboard
WshShell.Run "http://127.0.0.1:5000", 1, False
