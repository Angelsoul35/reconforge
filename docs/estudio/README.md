# Guía de estudio — reconforge

Esta carpeta es una guía en español para entender reconforge a fondo. El código,
los comentarios y la documentación técnica están en inglés (nivel B2) a propósito,
para que el proyecto sea creíble y sirva para practicar. Esta guía explica el "por
qué" de cada decisión en tu idioma.

## Orden sugerido de lectura

1. **[01-agregador-y-colectores.md](01-agregador-y-colectores.md)** — qué resuelve,
   el `Collector` Protocol y el modelo `Asset` único, y por qué los colectores son
   offline por defecto (autorización).
2. **[02-normalizar-y-puntuar.md](02-normalizar-y-puntuar.md)** — la normalización
   por host y el motor de puntuación de exposición basado en reglas.
3. **[03-preguntas-de-entrevista.md](03-preguntas-de-entrevista.md)** — preguntas
   típicas y cómo responderlas con seguridad.

## Resumen en una frase

reconforge agrega hallazgos de reconocimiento (autorizado) de varios colectores
enchufables en un solo modelo `Asset`, los fusiona y deduplica por host, y puntúa
la exposición de cada activo con reglas deterministas y explicables — un informe
de superficie de ataque priorizado, no un montón de salidas sueltas, y sin escanear
a nadie por defecto.
