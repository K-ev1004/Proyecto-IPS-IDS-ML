# M0 — Fuga de características (Dst Port) en CSE-CIC-IDS2018

**Generado:** 2026-11-04T18:07:30+00:00 · semilla 42 · LogReg (StandardScaler) holdout 80/20 estratificado

| Modelo | Accuracy | Macro-F1 | Features |
|---|---:|---:|---:|
| 23_features | 0.9436 | 0.8151 | 23 |
| sin_puertos | 0.9347 | 0.7982 | 22 |
| solo_dst_port_arbol | 0.8373 | 0.4805 | 1 |

**Lectura (defecto nº 3 confirmado):**

1. **Fuga directa**: un árbol que SOLO mira `Dst Port` alcanza **83,7 % de accuracy**
   con una sola feature. En el holdout sintético, el puerto cuasi-etiqueta la clase.
2. **Costo de quitarla es bajo**: el modelo completo pierde solo 0,9 puntos de
   accuracy (94,4 → 93,5) y 0,017 de macro-F1 al eliminar `Dst Port`. La señal
   volumétrica real está en las demás features.
3. **Ejemplo por clase**: SSH-Bruteforce llega a p=1,0 (puerto 22 lo delata) con
   puertos; sin ellos baja a p=0,982 con recall casi intacto (0,983). El modelo
   con puertos aprende reglas de puertos que NO generalizan (C3: reglas de
   puertos contra tráfico benigno real = FP masivos).

**Implicación M3**: entrenar las dos variantes (con/sin puertos) y decidir con
replay C3, no con accuracy del holdout. La tensión accuracy-sintético vs
generalización-real es el resultado interesante de la tesis.

## Por clase (precision/recall en holdout)

- **23_features**: Benign: p=0.991/r=0.979, DoS attacks-GoldenEye: p=0.761/r=0.501, DoS attacks-Hulk: p=0.913/r=0.991, DoS attacks-SlowHTTPTest: p=0.639/r=0.551, DoS attacks-Slowloris: p=0.941/r=0.752, FTP-BruteForce: p=0.704/r=0.777, SSH-Bruteforce: p=1.0/r=0.998
- **sin_puertos**: Benign: p=0.987/r=0.969, DoS attacks-GoldenEye: p=0.932/r=0.492, DoS attacks-Hulk: p=0.876/r=0.986, DoS attacks-SlowHTTPTest: p=0.637/r=0.55, DoS attacks-Slowloris: p=0.819/r=0.651, FTP-BruteForce: p=0.704/r=0.777, SSH-Bruteforce: p=0.982/r=0.983

Uso en la tesis: la tensión accuracy-holdout vs generalización C3 (M3 entrena con y sin puertos y decide con replay) es el resultado interesante.
