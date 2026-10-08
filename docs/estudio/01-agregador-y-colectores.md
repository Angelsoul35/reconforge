# 01 — El agregador y los colectores

## El problema

El reconocimiento (recon) de superficie de ataque produce datos **fragmentados**:
una herramienta de subdominios, un escáner de puertos, un fingerprinter de
tecnologías y una sonda TLS, cada una con su formato, y todas solapándose sobre
los mismos hosts. Luego una persona lo cose a mano. reconforge convierte ese paso
mecánico en una librería: **una** interfaz `Collector`, **un** modelo `Asset`
normalizado, una fusión y una pasada de puntuación.

## El `Collector` Protocol y el modelo `Asset`

La decisión de diseño que hace de esto una librería y no un script: una interfaz
mínima.

```python
class Collector(Protocol):
    name: str

    def collect(self, target: str) -> list[Asset]: ...
```

Cada colector devuelve `Asset` **parciales** (el escáner de puertos rellena
`ports`, la sonda TLS rellena `tls_issues`). El resto del sistema solo ve `Asset`.
Añadir una fuente real (DNS, datos pasivos tipo certificate transparency, un
fingerprinter HTTP) es **implementar el Protocol**; nada aguas abajo cambia.

Un `Asset` reúne: host, IPs, puertos, tecnologías, problemas de TLS, etiquetas y
las `sources` (qué colectores contribuyeron, útil como procedencia).

## Offline por defecto: autorización y seguridad

Una herramienta de recon actúa sobre redes, y escanear un host sin autorización es
en el mejor caso una grosería y en el peor un delito. Una herramienta que escanea
nada más ejecutarse invita al mal uso y hace las pruebas no deterministas y
dependientes de la red.

Por eso los colectores incluidos son **offline y deterministas**: cada uno deriva
una superficie plausible y repetible de un hash SHA-256 del objetivo. El mismo
objetivo da siempre los mismos activos, así que la demo y las pruebas son
reproducibles y **no escanean a nadie**. Los colectores reales (que tocan la red)
son una **elección explícita** (`RF_ALLOW_ACTIVE_SCAN`) y responsabilidad de un
despliegue con permiso.

Esto es parte de la madurez de seguridad: lo seguro por defecto, y la autorización
como una decisión consciente, no un accidente de ejecutar la herramienta.

## Para fijar la idea

- Recon = datos fragmentados de muchas herramientas; reconforge los unifica.
- Un `Collector` Protocol + un modelo `Asset` → añadir fuentes sin tocar el núcleo.
- Colectores offline y deterministas por defecto (hash del objetivo); los reales,
  opt-in con autorización.
