# 02 — Normalizar y puntuar

## Normalización: un activo por host

Varios colectores informan del mismo host: el escáner de puertos y la sonda TLS
describen los dos `www.example.com`. Si la puntuación corriera sobre la salida
cruda, el mismo host se puntuaría varias veces, su exposición quedaría repartida
en fragmentos y el informe **duplicaría** y engañaría. El ranking saldría mal.

Por eso hay un paso de **normalización** entre recoger y puntuar. Los `Asset` que
comparten host se fusionan en uno:

- IPs, tecnologías, problemas de TLS, etiquetas y `sources` se **unen** (dedup).
- Los puertos se deduplican por número (la primera fuente conserva la etiqueta de
  servicio).

La fusión es **conmutativa** (uniones de conjuntos y dedup por clave), así que el
resultado no depende del orden de los colectores. Queda un `Asset` por host con
todo lo que se supo de él, y la puntuación corre **una vez** por host.

## Puntuación: reglas, no un modelo

Cada activo se puntúa con un conjunto de **reglas con peso**. Cada regla (un puerto
sensible abierto, un problema de TLS, software obsoleto, un panel de admin
expuesto) aporta un peso y un `ExposureFinding` con una razón legible. El total es
la suma, y se mapea a un nivel por umbrales.

| Hallazgo                                      | Peso | Severidad |
| --------------------------------------------- | ---- | --------- |
| RDP (3389) / Telnet (23) expuestos            | 4    | high      |
| SMB (445), MySQL, PostgreSQL, Mongo, Redis    | 3    | high      |
| Certificado TLS caducado                      | 3    | high      |
| Panel administrativo expuesto                 | 3    | high      |
| Software fin-de-vida (p. ej. Apache 2.4.49)   | 2    | high      |
| FTP (21), HTTP sin HTTPS, TLS self-signed/1.0 | 2    | medium    |
| SSH (22) expuesto                             | 1    | low       |

Umbrales: `≥12 critical`, `≥8 high`, `≥4 medium`, `≥1 low`, si no `info`.

### ¿Por qué reglas y no ML?

Porque el riesgo de superficie de ataque es **conocimiento de dominio** bien
entendido (un RDP expuesto o un certificado caducado son malos sin necesidad de un
dataset), y un hallazgo de seguridad debe ser **explicable** al equipo que debe
actuar. Ventajas:

- **Cada puntuación es descomponible:** es exactamente la lista de hallazgos.
- **Sin datos de entrenamiento ni deriva:** las reglas codifican juicio durable.
- **Ajustable por organización:** pesos y umbrales son datos planos.
- **Ranking consistente:** la misma superficie se ordena siempre igual.

Es la misma separación que en pqrs-router: el juicio con consecuencias se mantiene
determinista y revisable. Una regla nueva para un riesgo nuevo es algo **revisado
y explícito**, no una inferencia opaca.

## Para fijar la idea

- Normalizar a un activo por host antes de puntuar → nada de doble conteo; fusión
  conmutativa; procedencia conservada.
- Puntuación por reglas con peso → descomponible, explicable, ajustable, sin ML.
