

## Criterios de etiquetado

- `tool` es la herramienta MCP cuyo parámetro recibe la entrada del atacante, y `parameter` es ese parámetro, aunque el sumidero esté en una función auxiliar o en otra herramienta.
- Una vulnerabilidad principal por caso. Los casos corregidos llevan `vulnerabilities: []` y explican en `notes` por qué son seguros y bajo qué supuestos.
- Alcance de v1: una corrección de SSRF basada en comprobar esquema, host e IP resuelta cuenta como corregida; el DNS rebinding y la resolución solo IPv4 quedan fuera de alcance. Una corrección de path traversal con `resolve()` e `is_relative_to` cuenta como corregida; la ventana TOCTOU con enlaces simbólicos queda fuera de alcance. Estas limitaciones se anotan en `notes`.
- Los casos son vulnerables a propósito y no se ejecutan fuera de un entorno aislado.
