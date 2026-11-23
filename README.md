# GitHub automation

![Made with AI](https://img.shields.io/badge/Made%20with-AI-76ddcf)

Automatycznie zbiera aktualizacje zależności, alerty bezpieczeństwa i błędy automatyzacji z repozytoriów oraz aktualizuje ich statusy na tablicy GitHub Projects.

## Zakres

Nowe aktywne repozytoria właściciela są wykrywane automatycznie. Parametr
`--exclude-repo OWNER/REPO` pozwala jawnie pominąć repozytorium bez zamykania
lub odrzucania alertów; można go podać wielokrotnie. Wyjątki są wymieniane na
prywatnej karcie stanu monitora, nie w publicznym logu.

Decyzją właściciela harmonogram pomija nieużywany fork
`ajsem1337/community-plugins`, zawierający cały katalog cudzych wtyczek.
Własne `ajsem1337/system-menu` pozostaje monitorowane.

## Prywatne repozytoria

Współdzielony workflow `.github/workflows/secret-check.yml` uruchamia Gitleaks,
gdy natywne skanowanie sekretów GitHuba nie jest dostępne w planie repozytorium.
Wywołujące repo przypina workflow do pełnego SHA i udostępnia tylko
`contents: read`; nie przekazuje sekretów. Skan obejmuje pobraną historię Git.

Binarka Gitleaks ma przypiętą wersję i sprawdzaną sumę SHA-256. Raport jest
redagowany i nie jest publikowany jako artefakt; log pokazuje wyłącznie
identyfikator reguły, plik, linię i commit. Wykrycie lub błąd skanera kończy
workflow niepowodzeniem, które istniejący monitor przenosi do prywatnego projektu.
To nie zastępuje CodeQL ani nie dodaje natywnych alertów Secret Scanning.
