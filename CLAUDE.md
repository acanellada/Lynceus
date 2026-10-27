# Reglas del proyecto Lynceus

- Proyecto Python 3.12, paquete `lynceus_sec` en `src/`. Gestor: uv. Tests: pytest.
- No añadas dependencias sin avisar y justificarlo.
- No toques `benchmark/` ni `docs/` salvo que la tarea lo pida.
- Nunca ejecutes los servidores de `benchmark/cases` fuera de un entorno aislado ni los expongas a una red.
- No ejecutes comandos de shell sin pedir confirmación. No leas ni escribas fuera de este repositorio.
- No incluyas claves, tokens ni rutas personales en código, tests ni commits.
- Todo cambio lleva tests. No sigas si fallan.
- Cualquier detector o validador se mide contra `benchmark/cases` (precisión y recall).
- Un hallazgo solo es `validated=True` si lo confirma un canario que crea y comprueba Lynceus, nunca el servidor analizado.
- Explica cada decisión de diseño en una línea al terminar.