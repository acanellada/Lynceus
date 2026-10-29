# Hoja de ruta de Lynceus (borrador v0.1)

Estado: borrador del autor. Se revisa tras las primeras conversaciones con desarrolladores de MCP. Los plazos son estimaciones sin garantía.

## Objetivo

Validador de seguridad para servidores MCP que reporta solo los fallos de implementación que consigue reproducir, y los entrega de forma que un desarrollador pueda usarlos: reproducción, SARIF y test de regresión.

## v1: detectar, confirmar y entregar

Hito 1 (detección y medida)
- Modelo interno de herramienta, cargador de etiquetas y métricas (precisión y recall).
- Detector con reglas de fuentes y sumideros MCP para tres clases: inyección de comandos y argumentos, SSRF y path traversal.
- Benchmark ampliado: al menos 5 variantes por clase, vulnerables y corregidas, incluidas variantes de elusión.

Hito 2 (confirmación)
- Ejecución en sandbox sin red ni credenciales del anfitrión.
- Canarios creados y comprobados por Lynceus.
- Script de reproducción por hallazgo y salida SARIF.

Puerta de v1: en el benchmark, todo fallo reportado como validado tiene reproducción, y ningún caso corregido se reporta como validado.

## v1.5

- GitHub Action y modo diferencial en pull requests.
- Del exploit al test de regresión.
- Formato de reglas abierto con etiquetas CWE.

## Capa opcional de agentes

Solo después de tener una línea base sin LLM medida.
- Roles estrechos que proponen y no deciden: analista de código (fuentes y sumideros), generador de cargas y triaje con explicación.
- Pizarra compartida con hechos tipados; las solicitudes entre agentes son tipadas y las atienden servicios deterministas.
- Desactivada por defecto. Funciona con la clave o el modelo local del usuario.
- Puerta: se mantiene solo si mejora precisión o recall en el benchmark frente a la línea base y el coste por análisis es asumible.

## v2

- Autenticación, origen y autorización en servidores HTTP.
- Parche propuesto y validado repitiendo el ataque.
- Adaptador de TypeScript, si los datos lo justifican.

## No objetivos

- Escaneo de metadatos y tool poisoning (ya cubiertos por otras herramientas).
- Proxy o firewall en ejecución.
- Informes firmados, hasta que exista demanda comprobada.

## Puertas de decisión

- Tras la prueba de reglas taint: detector basado en reglas o analizador propio.
- Tras las tres conversaciones con desarrolladores: si cambia el orden de v1.5.
- Tras el hito 2: si merece la pena el adaptador de TypeScript.

## Preguntas abiertas

- Nivel mínimo de aislamiento del sandbox.
- Coste por análisis de la capa de agentes.
- Modelo de negocio: núcleo abierto con capa de pago, sin decidir.