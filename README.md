# dpop-server-antireplay

Estudio de medición: cómo se comportan verificadores DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) del lado servidor frente a replay de pruebas, `jti` repetidos, nonces y desfase de reloj. Se miden dos crates publicados, [`dpop-auth` 0.1.3](https://crates.io/crates/dpop-auth) y [`skyauth` 0.3.9](https://crates.io/crates/skyauth), y un verificador de referencia chico que vive en este repo. Las pruebas son ES256 reales; nada se simula salvo quién es el cliente.

Measurement study of server-side DPoP (RFC 9449) anti-replay behaviour (replay, `jti`, nonces, clock skew, replay-store flooding) on `dpop-auth` 0.1.3, `skyauth` 0.3.9 and a small reference verifier. English summary at the end.

---

## ES

### Por qué es un estudio y no "otra librería"

La idea original era un middleware servidor con nonce y almacén de `jti`. Antes de escribirlo leí las páginas públicas (README en crates.io) y el código fuente publicado de los dos crates que ya existen:

- **dpop-auth 0.1.3** (README): "DPoP proof validation: typ, alg, jwk, htm, htu, iat, ath, with replay protection via jti caching", con middleware para Axum. En el código: el caché de `jti` es un `moka::future::Cache` con `max_capacity(100_000)` y TTL `2 × clock_skew + 5 s` (`src/cache/jti.rs`, `src/state.rs`); los nonces viven 300 s y son reutilizables (`src/cache/nonce.rs`).
- **skyauth 0.3.9** (README): "Single-Use Server Nonces: Optional strict RFC 9449 § 8 nonce consumption" y "a Tower middleware layer enforcing DPoP proof verification, replay rejection, and server nonce challenges". En el código: caché de replay por `(jkt, jti)`, 64 shards de 2048 entradas que "fail closed at capacity rather than evicting live proofs" (`src/dpop.rs`); la admisión al caché se confirma después de validar el access token (`src/integrations/tower.rs`).

Con eso, **no hay un hueco real de "falta un middleware servidor con nonce y jti"**: skyauth ya tiene nonce de servidor (incluso de un solo uso), caché `(jkt, jti)` y cierre a capacidad. Lo que sí no encontré publicado es una medición comparable de esas propiedades bajo carga. Este repo es eso: un arnés que manda las mismas pruebas a los tres verificadores y cuenta veredictos. El verificador de referencia no se propone como reemplazo; sirve como control y para medir una sola decisión de diseño (cuota por clave, abajo).

### Qué hay

| Pieza | Qué hace |
|---|---|
| `src/proof.rs` | Pruebas ES256 con control de cada claim y del header (`typ`, `jwk` con `d`, `ath`, `iat`, `nonce`, `alg: none`, firma alterada). Thumbprint RFC 7638. |
| `src/sut.rs` | Adaptadores. dpop-auth: `dpop::validate_dpop_proof`, la función que llama su `DpopLayer` después de verificar el token. skyauth: `verify_proof_deferred` → chequeo de nonce → `commit_replay_admission`, el orden de su capa Tower. Referencia: `RefVerifier`. |
| `src/reference.rs` | Verificador de referencia: almacén `(jkt, jti)` que vence en `iat + max_age + 1`, cuota de entradas vivas por `jkt` (4096) y capacidad total (131 072) que rechaza en vez de desalojar; nonces HMAC rotativos sin estado compartido (período actual y anterior). |
| `src/scenarios.rs` | Escenarios (abajo). |
| `src/bin/dsa-bench.rs` | Corre todo, escribe CSV. `--check` sale con 1 si falla una expectativa exacta de la referencia o si un flood terminó fuera de la ventana de `iat` de las víctimas. |
| `tests/` | 26 tests: los mismos chequeos de request contra los tres, más almacén, nonces, thumbprint y `ath`. |
| `scripts/repeat.sh` | Cinco repeticiones de los dos escenarios con carrera (replay concurrente y flood). |

Fuera del alcance de los adaptadores: la firma del access token y `cnf.jkt`. El arnés modela un cliente que ya tiene un token válido (en dpop-auth el token se verifica antes de la prueba; en skyauth antes de confirmar el `jti`).

### Escenarios

- `valid_fresh` / `replay_sequential`: 1000 pruebas nuevas, después cada una reenviada una vez.
- `replay_concurrent`: 200 pruebas; cada una la mandan 16 hilos a la vez (barrera). Se cuenta cuántas pruebas se aceptaron más de una vez.
- `iat_offset`: 20 pruebas por desfase de `iat` en {−600, −310, −290, −120, −65, −55, −30, 0, +30, +55, +65, +120, +600} s.
- Nonces (instancias con nonce obligatorio): sin nonce, con nonce recién pedido, un nonce reusado en pruebas con `jti` nuevo, nonce inventado, y nonce usado después de esperar 12 s (TTL de skyauth configurado en 5 s, período de la referencia 5 s; dpop-auth tiene 300 s fijo).
- `flood`: un cliente A manda 50 pruebas aceptadas (reloj 50 s adelantado, válidas en las tres ventanas). Después un cliente B **con token válido** manda 150 000 pruebas nuevas. Luego: se reenvían las 50 de A (`flood_replay_old`), un cliente C manda 50 nuevas (`flood_honest_after`) y se reenvían esas (`flood_replay_new`).
- `throughput`: verificaciones por segundo de pruebas válidas ya firmadas, 1 y 4 hilos.

### Resultados

Máquina: 8 núcleos, Linux 6.12, rustc 1.99.1, `--release`. Comando:

```sh
cargo run --release --bin dsa-bench -- --check --csv results/full.csv
./scripts/repeat.sh                     # 5 repeticiones de replay concurrente y flood
cargo run --release --bin dsa-bench -- --only dpop-auth --n 10 --concurrent 10 --per-offset 1 --throughput 100 --nonce-n 1 --stale-wait 0 --flood 90000  --csv results/dpop-auth-flood-90000.csv
cargo run --release --bin dsa-bench -- --only dpop-auth --n 10 --concurrent 10 --per-offset 1 --throughput 100 --nonce-n 1 --stale-wait 0 --flood 110000 --csv results/dpop-auth-flood-110000.csv
cargo run --release --bin dsa-bench -- --only dpop-auth --n 10 --concurrent 10 --per-offset 1 --throughput 100 --nonce-n 20 --stale-wait 310 --flood 1000 --csv results/dpop-auth-nonce-wait310.csv
```

(En las tres últimas solo cuentan las filas de flood o de nonce; el resto usa tamaños chicos.) `--check` salió con `CHECK OK`.

**En CI** (runner de GitHub, corrida 40818181482, tamaños más chicos: 100 pruebas concurrentes) se reprodujo lo mismo: dpop-auth aceptó 36/100 pruebas más de una vez y 50/50 replays después del flood; `--check` pasó para la referencia.

**Lo básico pasa en los tres** (`results/full.csv`): 1000/1000 pruebas nuevas aceptadas, 0/1000 replays secuenciales aceptados, y 0 aceptaciones de firma alterada, `alg: none`, `typ` distinto, `jwk` con clave privada, `htm`/`htu`/`ath` incorrectos o nonce inventado (tests).

**Replay concurrente** (200 pruebas × 16 hilos, 5 corridas, `results/repeat/`):

| Verificador | Pruebas aceptadas más de una vez, por corrida |
|---|---|
| dpop-auth 0.1.3 | 25, 11, 13, 20, 10 (de 200) |
| skyauth 0.3.9 | 0, 0, 0, 0, 0 |
| referencia | 0, 0, 0, 0, 0 |

Causa (leída en el código, no inferida del número): dpop-auth chequea el `jti` con `cache.entry(jti).or_insert(true).await.is_fresh()`. En moka 0.12.16 `or_insert` es `get_with_hash` y, si no está, `insert_with_hash` (`src/future/cache.rs`, `get_or_insert_with_hash`): leer y escribir no son atómicos, así que dos requests simultáneos con la misma prueba pueden ver "fresh" los dos.

**Flood autenticado de 150 000 pruebas de una sola clave** (5 corridas):

| Verificador | Replays aceptados de las 50 pruebas previas de A | Pruebas nuevas de C aceptadas | Replays de C aceptados |
|---|---|---|---|
| dpop-auth 0.1.3 | 50, 50, 50, 50, 50 | 50 en las 5 | 0, 0, 40, 40, 0 |
| skyauth 0.3.9 | 0 en las 5 | **0** en las 5 (503 por caché saturado) | — |
| referencia | 0 en las 5 | 50 en las 5 | 0 en las 5 |

- dpop-auth: con 90 000 pruebas de flood los replays de A aceptados fueron 0/50; con 110 000, 50/50 (`results/dpop-auth-flood-*.csv`). El umbral coincide con `max_capacity(100_000)`: al llenarse, moka desaloja entradas vivas y las pruebas de A vuelven a pasar mientras su `iat` sigue en ventana. En 2 de 5 corridas además 40/50 pruebas nuevas de C se pudieron reenviar (la política de admisión de moka no las retuvo). RFC 9449 §11.1 pide guardar el `jti` "for the time window in which the respective DPoP proof JWT would be accepted".
- skyauth: no hay replay, pero el caché cierra a capacidad para todos: con 150 000 pruebas, 131 022 se aceptaron, 18 978 dieron "saturated", y después un cliente distinto recibió 0/50. Las entradas viven `now + 300 + 60` s, así que un solo poseedor de token puede sostener la indisponibilidad con unas 364 pruebas por segundo. Es una decisión explícita del crate (cerrar en vez de desalojar); el costo es disponibilidad.
- referencia: la cuota por `jkt` deja pasar 4096 pruebas del atacante y rechaza las 145 904 restantes; A no se puede reenviar y C sigue entrando. Costo declarado: un cliente legítimo que manda más de 4096 requests dentro de la ventana (~121 s, unos 34 req/s sostenidos) también queda limitado. La cuota sirve porque la clave está ligada a un token; contra pruebas sin token no protege nada.

**Ventana de `iat`** (aceptadas de 20, `results/full.csv`):

| | −600 | −310 | −290 | −120 | −65 | −55 | −30 | 0 | +30 | +55 | +65 | +120 | +600 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| dpop-auth | 0 | 0 | 0 | 0 | 0 | 20 | 20 | 20 | 20 | 20 | 0 | 0 | 0 |
| skyauth | 0 | 0 | 20 | 20 | 20 | 20 | 20 | 20 | 20 | 20 | 0 | 0 | 0 |
| referencia | 0 | 0 | 0 | 0 | 0 | 20 | 20 | 20 | 20 | 20 | 0 | 0 | 0 |

Los tres toleran ±30 s y rechazan ±10 min. skyauth acepta pruebas de hasta 300 s de antigüedad (su `DEFAULT_MAX_PROOF_AGE`).

**Nonces** (20 por fila): sin nonce → 20/20 desafiadas en los tres; con nonce recién pedido → 20/20 aceptadas; nonce reusado con `jti` nuevo → 20/20 aceptadas en los tres (RFC 9449 §11.1 lo permite); nonce inventado → 0/20. Después de 12 s: dpop-auth 20/20 aceptadas (TTL fijo 300 s), skyauth 0/20, referencia 0/20. Con 310 s de espera dpop-auth acepta 0/20.

**Throughput** (verificaciones/s, `results/full.csv`, una corrida):

| | 1 hilo | 4 hilos |
|---|---|---|
| dpop-auth | 15 844 | 62 644 |
| skyauth | 6 405 | 24 150 |
| referencia | 16 715 | 57 077 |

Los tres superan 5000/s en un hilo. No es una comparación de criptografía: dpop-auth usa jsonwebtoken, la referencia usa ring, skyauth su propia verificación P-256.

### Límites

- Una sola máquina; los números de throughput son de una corrida y varían entre corridas (en una corrida con compilación en paralelo dpop-auth dio 12 373/s en un hilo).
- Los adaptadores llaman a las funciones de las librerías, no a sus servidores HTTP. Se replicó el orden de cada middleware leyendo su código; un error en esa lectura cambiaría los resultados.
- Un solo nodo. Entre réplicas sin estado compartido ninguno de los tres impide replay (skyauth lo dice en su documentación); eso está medido en [cortex9-dpop-replay-mesh](https://github.com/federiconbaez/cortex9-dpop-replay-mesh).
- No hay prueba de interoperabilidad contra un servidor de autorización real (Keycloak/Duende).
- Las hipótesis de desalojo en dpop-auth y de saturación en skyauth salieron de leer el código antes de correr; la carrera del replay concurrente apareció en la primera corrida y después se buscó la causa en el código de moka.

### Fuentes leídas

- RFC 9449, texto completo (secciones 4.3, 11.1, 11.2).
- README de dpop-auth 0.1.3 y de skyauth 0.3.9 en crates.io, y el código publicado de ambos (archivos citados arriba).
- moka 0.12.16, `src/future/entry_selector.rs` y `src/future/cache.rs`.
- El vector de `ath` de RFC 9449 §7.1 se toma tal como lo cita skyauth en su documentación.

---

## EN

**Why a study and not another library.** I read the crates.io READMEs and published source of `dpop-auth` 0.1.3 and `skyauth` 0.3.9 before writing anything. skyauth already ships server nonces (optionally single-use), a `(jkt, jti)` replay cache and fail-closed capacity, so a "missing server-side DPoP middleware" gap does not exist. What I did not find published is a comparable measurement under load; that is this repo. The reference verifier is a control, plus one measured design choice (per-key quota).

**Findings** (commands above, CSVs in `results/`):

- All three accept 1000/1000 fresh proofs and 0/1000 sequential replays, and reject tampered signatures, `alg: none`, wrong `typ`, private JWKs, wrong `htm`/`htu`/`ath` and forged nonces.
- Concurrent replay (200 proofs × 16 threads, 5 runs): dpop-auth accepted 25, 11, 13, 20, 10 proofs more than once; skyauth and the reference 0. Cause: dpop-auth's `entry().or_insert()` on moka 0.12.16 is get-then-insert, not atomic.
- Authenticated flood of 150 000 proofs from one key (5 runs): dpop-auth re-accepted 50/50 earlier proofs every run (0/50 at 90 000, 50/50 at 110 000; its cache cap is 100 000). skyauth never replayed but returned "saturated" to a different client 50/50 times (one token holder can keep it unavailable). The reference capped the flooding key at 4096 and kept serving others with 0 replays; cost: legitimate clients above ~34 req/s sustained are limited too.
- `iat` window: all three tolerate ±30 s and reject ±600 s; skyauth accepts proofs up to 300 s old.
- Throughput (1 thread): dpop-auth 15 844/s, skyauth 6 405/s, reference 16 715/s.

**Limits:** one machine, one node, library calls instead of HTTP servers, no interop run against a real AS.

## Licencia / License

Apache-2.0.
