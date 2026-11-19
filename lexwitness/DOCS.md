# LexAssistant martor

Martor pentru failoverul LexAssistant (docs/ha-kiss-design.md, regulile 1-2). Nu păstrează nimic pe disc: după
fiecare pornire stă 75 s în carantină, apoi verifică adresa publică și ține permisul de PRIMARY.

## Opțiuni
- `id`: numele martorului, unic (ex. `ha-acasa`, `ha-birou`), litere mici, cifre și cratimă.
- `key_hex`: cheia HMAC a acestui martor (64 de caractere hex), primită de la administrator. Goală = doar observare.
- `public_health_url`: lăsați valoarea implicită.
- `node_endpoints`: adresele `ha-main` / `ha-backup` primite de la administrator. Gol = doar observare (test).
- `probe_interval_seconds`: cât de des verifică adresa publică cât totul e în regulă (după o eroare: 10 s).
- `probe_offset_seconds`: decalajul primei verificări, diferit la fiecare martor (ex. 0, 60, 120, ...).

În jurnal apar pornirea și schimbările stării căii publice (up / failing / DOWN).
