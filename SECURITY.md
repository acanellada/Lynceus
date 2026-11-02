# Política de seguridad

## Versiones con soporte

Lynceus está en desarrollo temprano. Solo se corrigen fallos en la rama `main`.

## Cómo informar de una vulnerabilidad

No abras un issue público. Usa el aviso privado de GitHub: pestaña **Security** de este repositorio, **Report a vulnerability**.

Incluye, si puedes, la versión o el commit afectado, los pasos para reproducirlo y el impacto que observas. Intentaré acusar recibo en un plazo de 7 días; los plazos de corrección dependen de la gravedad, porque el proyecto lo mantiene una sola persona.

## Qué entra en el alcance

- Escapes del sandbox: un servidor analizado que consiga ejecutar código, leer o escribir fuera del contenedor, alcanzar la red o persistir tras la validación.
- Fallos en la comprobación de aislamiento de la red interna de SSRF.
- Inyección en los informes: texto del servidor analizado que ejecute código en el informe HTML o altere la terminal.
- Atribución manipulable: un servidor que consiga que un hallazgo se atribuya a otra herramienta o parámetro.
- Vulnerabilidades en las dependencias del proyecto o del sandbox.

## Qué no entra en el alcance

- Los casos de `benchmark/cases/`: son vulnerables a propósito.
- Los falsos negativos o positivos de la detección. Son fallos de calidad, no de seguridad: ábrelos como issue normal.
- Usar Lynceus contra sistemas sin autorización.
