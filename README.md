# LexAssistant - martor HA (add-on Home Assistant)

Martor pentru failoverul automat LexAssistant: verifică adresa publică a platformei și ține permisul de PRIMARY.
Nu păstrează nimic pe disc și deschide doar conexiuni de ieșire (merge în spatele oricărui router).

## Instalare (Home Assistant OS / Supervised)

[![Adaugă repository-ul în Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Feugentib%2Flexwitness-ha)

Sau manual: Settings → Add-ons → Add-on Store → ⋮ → Repositories → adăugați
`https://github.com/eugentib/lexwitness-ha`.

Apoi: „LexAssistant martor” → Install → Configuration (vezi DOCS) → Start → Log.

Cheile și adresele nodurilor se primesc de la administrator; fără ele martorul doar observă.
