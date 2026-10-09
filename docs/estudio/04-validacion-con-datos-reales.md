# 04 — Validación con datos reales (CVSS)

Los capítulos 01–03 explican **qué** hace reconforge y **por qué** su motor de
puntuación es por reglas. Este capítulo responde a la pregunta dura: ¿ese motor
**generaliza** a datos reales, o solo funciona en la demo? Lo validamos contra el
estándar de la industria para la severidad de hallazgos de seguridad: **CVSS**.

## La idea en una frase

El motor de reconforge asigna una severidad a un conjunto de hallazgos sumando
pesos y aplicando umbrales (`aggregate` en `scoring.py`). **CVSS hace exactamente
lo mismo** con las vulnerabilidades: toma unas métricas, calcula una puntuación
0–10 y la mapea a `None/Low/Medium/High/Critical`. Así que tomamos 12 000
vulnerabilidades reales del NVD, calibramos los pesos de reconforge para
reproducir la severidad CVSS, y medimos si lo consigue **en datos que no vio al
calibrar**.

## El dato real

- **Fuente:** `bziemba/cve_cwe_cvss` en Hugging Face — una compilación tabular de
  registros públicos del **NVD / CVE Program (MITRE)** con el vector de métricas
  base **CVSS v3.1** desglosado en sus ocho componentes.
- **Instantánea vendida:** `datasets/cvss_cwe_snapshot.jsonl`, 12 000 filas, con
  muestreo determinista repartido por todo el corpus (ver `datasets/README.md`).
- **Carga:** `reconforge/real_data.py::load_cvss_dataset`.

Cada registro (`CvssRecord`) tiene ocho métricas:

| métrica | significado | valores |
| --- | --- | --- |
| AV | Attack Vector (vector de ataque) | Network / Adjacent Network / Local / Physical |
| AC | Attack Complexity | Low / High |
| PR | Privileges Required | None / Low / High |
| UI | User Interaction | None / Required |
| S | Scope (alcance) | Unchanged / Changed |
| C / I / A | impacto en Confidencialidad / Integridad / Disponibilidad | High / Low / None |

## La etiqueta de oro: la fórmula oficial CVSS v3.1

La verdad de referencia **no es inventada**: es la severidad que produce la
fórmula oficial de FIRST.org (`cvss_base_score` en `real_data.py`). Cada valor de
métrica tiene un número asignado por el estándar:

```
AV: Network 0.85 | Adjacent 0.62 | Local 0.55 | Physical 0.2
AC: Low 0.77 | High 0.44
UI: None 0.85 | Required 0.62
C/I/A: High 0.56 | Low 0.22 | None 0.0
PR (Scope Unchanged): None 0.85 | Low 0.62 | High 0.27
PR (Scope Changed):   None 0.85 | Low 0.68 | High 0.50
```

Y la puntuación se calcula así:

```
ISS         = 1 − (1−C)·(1−I)·(1−A)
Impact      = 6.42 · ISS                                  (Scope Unchanged)
            = 7.52·(ISS−0.029) − 3.25·(ISS−0.02)^15       (Scope Changed)
Exploit.    = 8.22 · AV · AC · PR · UI
BaseScore   = Roundup( min(Impact + Exploit., 10) )       (×1.08 si Scope Changed)
Severidad   = None 0.0 | Low 0.1–3.9 | Medium 4.0–6.9 | High 7.0–8.9 | Critical 9.0–10.0
```

### Ejemplo numérico con un CVE real

`CVE-2025-50475` (inyección de comandos sin autenticación) tiene el vector
`AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H`. Con los números del estándar:

```
ISS      = 1 − (1−0.56)·(1−0.56)·(1−0.56) = 1 − 0.44^3 = 1 − 0.085184 = 0.914816
Impact   = 6.42 · 0.914816 = 5.8731           (Scope Unchanged)
Exploit. = 8.22 · 0.85 · 0.77 · 0.85 · 0.85 = 3.8871
Base     = Roundup(5.8731 + 3.8871) = Roundup(9.7602) = 9.8  → CRITICAL
```

reconforge mapea la "None" de CVSS a su nivel `INFO` (un activo sin nada que
marcar). El conjunto de etiquetas es, pues, `{INFO, LOW, MEDIUM, HIGH, CRITICAL}`.

Distribución real de la instantánea (12 000 filas):

| severidad | nº | proporción |
| --- | --- | --- |
| info (None) | 58 | 0.005 |
| low | 659 | 0.055 |
| medium | 5680 | **0.473** |
| high | 4321 | 0.360 |
| critical | 1282 | 0.107 |

La clase mayoritaria es `medium` con 0.473: ese es el **baseline** que hay que
batir.

## El motor reutilizado, con pesos calibrados

`reconforge/severity_model.py` convierte cada métrica en un `ExposureFinding`
(razón legible + peso) y los puntúa con **el mismo `aggregate`** que usan las
reglas de puertos/TLS/tech. La única diferencia: en producción los pesos son
enteros puestos a mano; aquí se **calibran** con mínimos cuadrados para que la
suma reproduzca la puntuación base CVSS. Es la misma tesis del README ("los pesos
son datos, fáciles de ajustar a un modelo de riesgo"), llevada a un corpus real.

Como la predicción es una **suma** (modelo aditivo) y la exploitabilidad de CVSS
es un **producto** (`AV·AC·PR·UI`), el motor aditivo *aproxima* esa parte no
aditiva. No lo escondemos: lo medimos (el error MAE más abajo) y señalamos cómo
cerrarlo (añadir hallazgos de interacción por pares).

## Las métricas, con fórmula

Para cada clase `L`:

```
precision(L) = TP / (TP + FP)      recall(L) = TP / (TP + FN)
F1(L)        = 2 · precision · recall / (precision + recall)
macro-F1     = promedio de F1(L) sobre las clases presentes
accuracy     = aciertos / total
```

`macro-F1` promedia **por clase** (no por fila), así que una clase rara pesa igual
que una común. Por eso es más exigente que `accuracy` cuando los datos están
desbalanceados — y aquí lo están (medium 47 %, info 0.5 %).

### Por qué el baseline tiene macro-F1 tan bajo

El baseline predice siempre `medium`. Entonces solo la clase `medium` tiene
aciertos: su F1 ≈ 0.64, y las otras cuatro clases tienen F1 = 0. El promedio sobre
5 clases es `0.64/5 ≈ 0.129`. Su `accuracy`, en cambio, es 0.473 (acierta todas
las `medium`). Comparar contra ambos números es lo justo.

## CV frente a held-out (el corazón de la generalización)

Separamos un **test retenido** (held-out, 20 %) que el motor no ve al calibrar.
Sobre el 80 % restante hacemos **validación cruzada estratificada de 5 pliegues**:
calibramos en 4 pliegues, medimos en el que queda, y repetimos. "Estratificada"
= cada pliegue conserva la proporción de clases (`stratified_folds`).

Resultados reales (`python -m reconforge.real_benchmark`):

```
baseline (medium):      accuracy 0.473   macro-F1 0.129
CV 5-fold macro-F1:     0.647 ± 0.032    pliegues [0.691, 0.647, 0.600, 0.626, 0.669]
train:                  accuracy 0.851   macro-F1 0.674
held-out:               accuracy 0.857   macro-F1 0.682
gap train − held-out:   −0.008 (macro-F1)
MAE base-score held-out: 0.393  (en escala 0–10)
F1 por clase (held-out): info 0.00 · low 0.82 · medium 0.89 · high 0.81 · critical 0.89
```

Lecturas:

- El motor **bate el baseline con holgura**: macro-F1 0.682 vs 0.129 (margen
  +0.553) y accuracy 0.857 vs 0.473.
- La **CV y el held-out concuerdan**: 0.647 vs 0.682, diferencia 0.035, dentro de
  la desviación entre pliegues (±0.032). La concordancia CV↔held-out es la prueba
  de que generaliza, no el valor del gap de entrenamiento por sí solo.
- El motor aproxima la puntuación CVSS real con un **error de ~0.4 puntos** sobre
  10 — señal fuerte, no una coincidencia perfecta (que sería sospechosa).
- La clase `info` (None, el 0.5 %) sale a F1 0: un modelo aditivo casi nunca
  predice una puntuación exactamente 0, así que no acierta esa banda. Es un
  límite concreto y la vía para extenderlo (una compuerta "impacto nulo → INFO")
  está señalada; las cuatro bandas sustantivas van de 0.81 a 0.89.

## Overfitting / underfitting y el gap train–test

- **Overfitting (sobreajuste):** el modelo memoriza el entrenamiento. Señal:
  `train` muy por encima de `held-out` **y** `held-out` por debajo de la CV. Aquí
  el gap es **−0.008** (el held-out es incluso algo mejor que train), así que no
  hay memorización. Con solo 22 pesos sobre miles de filas, el modelo es de baja
  varianza por diseño.
- **Underfitting (subajuste):** el modelo no capta la señal; se queda cerca del
  baseline. No es el caso con datos reales (0.682 ≫ 0.129), pero **sí es
  exactamente lo que deben mostrar los controles negativos**.
- El veredicto **no** se decide por "el gap de entrenamiento es cero". Un modelo
  que satura puede tener un gap estrecho y aun así generalizar; lo que importa es que
  **CV y held-out coincidan** y que ambos superen el baseline.

## El control negativo (la prueba antifraude)

Un resultado alto no vale nada si no cae al azar cuando rompemos la relación entre
rasgos y etiqueta. Como aquí la etiqueta es una **función** de las métricas (la
fórmula CVSS), no basta con permutar las métricas: la etiqueta las seguiría. Por
eso `real_benchmark.py` desacopla los arreglos almacenados `(score, etiqueta)` de
los registros:

- **Etiquetas barajadas (`shuffle_labels`):** cada registro conserva sus métricas
  pero recibe el `(score, etiqueta)` de otro. Los rasgos ahora predicen un
  objetivo sin relación.
- **Entradas revueltas (`scramble_inputs`):** se permuta cada columna de métrica
  por separado y se mantienen las etiquetas originales. La estructura conjunta se
  destruye.

Resultado real:

```
control etiquetas barajadas: macro-F1 0.129
control entradas revueltas:  macro-F1 0.129
```

Ambos **colapsan al baseline** (0.129). El motor no puede inventar señal donde no
la hay: justo lo que debe pasar. Si un control no colapsara, el 0.682 sería
sospechoso de ser un artefacto del montaje.

## Cómo se deriva el veredicto

`derive_verdict` aplica esta lógica (con macro-F1):

1. **¿Hay señal?** `held-out ≥ baseline + 0.10` **y** `held-out ≥ 1.5 · baseline`.
   Si no → **underfit** (sin señal aprendible; es el caso de los controles).
2. Si hay señal y `gap(train−held-out) > 0.10` **y** `held-out < CV − 2·sd` →
   **overfit** (memorización).
3. Si no → **well-fit**: supera el baseline, y CV y held-out concuerdan.

Con los números reales: hay señal (0.682 ≥ 0.229 y ≥ 0.194), el gap es −0.008
(no > 0.10), y CV↔held-out concuerdan → **well-fit**. Si en su lugar metemos el
macro-F1 de un control (0.129) como "held-out", la regla 1 falla y da **underfit**
— el test `test_verdict_logic_discriminates` comprueba precisamente eso, para que
el veredicto no selle ruido como si fuera aprendizaje.

```
VEREDICTO: WELL-FIT
  held-out macro-F1 0.682 supera el baseline 0.129 (margen +0.553);
  CV 0.647 ± 0.032 concuerda con held-out (|dif| 0.035);
  gap train/held-out −0.008 es estrecho.
```

## Para fijar la idea

- Validamos el motor de reconforge contra CVSS, el estándar real de severidad,
  sobre 12 000 CVEs reales del NVD, reutilizando el mismo `aggregate`.
- Etiqueta de oro = fórmula oficial CVSS v3.1 (no inventada); baseline = clase
  mayoritaria (`medium`, accuracy 0.473 / macro-F1 0.129).
- El motor calibrado: held-out accuracy 0.857, macro-F1 0.682, MAE 0.393;
  CV 0.647 ± 0.032 concuerda con el held-out; gap −0.008.
- Los dos controles negativos colapsan a 0.129 → la señal es real.
- Veredicto **well-fit**, derivado de la concordancia CV↔held-out y del margen
  sobre el baseline, no de un número redondo.
