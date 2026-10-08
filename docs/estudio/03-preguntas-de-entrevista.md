# 03 — Preguntas de entrevista

Preguntas típicas sobre este proyecto y cómo responderlas con seguridad.
Practica diciéndolas en voz alta en inglés también.

## Sobre el diseño

**¿Qué hace reconforge y por qué es una librería y no un script?**
Agrega hallazgos de recon de varias fuentes en un solo modelo `Asset`, los fusiona
y deduplica por host, y puntúa la exposición con reglas. Es una librería gracias a
una interfaz `Collector` mínima y un modelo `Asset` único: añadir una fuente es
implementar el Protocol, sin tocar la normalización ni la puntuación.

**¿Por qué los colectores son offline por defecto?**
Porque escanear un host sin autorización es grave, y una herramienta que escanea
al ejecutarse invita al mal uso y hace las pruebas no deterministas. Los colectores
incluidos derivan una superficie repetible de un hash del objetivo: no tocan la
red. Los reales son opt-in explícito, con autorización.

## Sobre la normalización

**¿Por qué normalizar antes de puntuar?**
Porque varios colectores informan del mismo host; sin fusionar, se puntuaría varias
veces y la exposición quedaría fragmentada, inflando y falseando el ranking.
Fusiono a un `Asset` por host (uniones de conjuntos, dedup de puertos por número) y
puntúo una vez. La fusión es conmutativa, así que no depende del orden.

## Sobre la puntuación

**¿Por qué reglas y no un modelo de ML?**
Porque el riesgo de superficie es conocimiento de dominio bien entendido y un
hallazgo de seguridad debe explicarse. Las reglas con peso dan una puntuación
descomponible (la lista de hallazgos), sin datos de entrenamiento ni deriva, y
ajustable por organización. Un riesgo nuevo es una regla nueva, revisada y
explícita, no una inferencia opaca.

**¿Cómo decides los pesos?**
Reflejan el impacto: acceso remoto en claro (RDP, Telnet) y bases de datos
expuestas pesan más; SSH expuesto, poco. Son datos planos, se calibran al modelo de
riesgo de la organización. Los umbrales de nivel también.

## Sobre seguridad responsable

**¿Cómo evitas que esto se use mal?**
Offline por defecto, autorización como opt-in explícito, y lo dejo claro en el
README: solo apuntar colectores reales a sistemas propios o con permiso escrito.
Una herramienta de seguridad debe ser segura por defecto.

## Pregunta trampa

**Si dos colectores informan del puerto 80 con etiquetas de servicio distintas,
¿qué pasa?**
La deduplicación por número conserva la **primera** fuente para la etiqueta, así
que el puerto aparece una sola vez. Es una decisión consciente para no duplicar; si
hiciera falta conservar discrepancias de servicio, el modelo `Asset` se podría
extender sin cambiar el resto del pipeline.
