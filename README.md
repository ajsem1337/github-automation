# GitHub automation

![Made with AI](https://img.shields.io/badge/Made%20with-AI-76ddcf)

Wspólne automatyzacje repozytoriów ajsem1337. Obecnie: synchronizacja aktualizacji
i alertów bezpieczeństwa z prywatną tablicą GitHub Projects.

Prywatna tablica: https://github.com/users/ajsem1337/projects/1

Workflow `Security project monitor` odświeża ją co 6 godzin (00:23, 06:23, 12:23,
18:23 UTC). Harmonogram GitHuba może mieć opóźnienia. Można też użyć **Run workflow**.
To zwykły skrypt korzystający z API GitHuba. Nie uruchamia AI ani płatnych runnerów.
Standardowe runnery w tym publicznym repo są bezpłatne.

## Jednorazowe uruchomienie

1. Utwórz osobny **Personal access token (classic)**:
   https://github.com/settings/tokens/new?description=Security%20project%20monitor&scopes=repo,project
2. Zaznacz zakresy **repo** oraz **project**, ustaw termin ważności, np. 90 dni.
   Token `classic` jest potrzebny, ponieważ fine-grained tokeny nie obsługują
   obecnie projektów należących do kont osobistych. `repo` daje szeroki dostęp do
   repozytoriów, również prywatnych — GitHub nie udostępnia tutaj węższego wariantu
   classic tylko do odczytu. Sam skrypt odczytuje repozytoria i zapisuje tylko tablicę.
3. Dodaj **Repository secret** o nazwie **SECURITY_PROJECT_TOKEN**:
   https://github.com/ajsem1337/github-automation/settings/secrets/actions/new
   Wartością jest wygenerowany token. Nie wklejaj go do kodu, Issues ani rozmowy.
4. Uruchom workflow:
   https://github.com/ajsem1337/github-automation/actions/workflows/security-project.yml
   Zielony wynik potwierdza wykonanie. W karcie „Monitoring bezpieczeństwa” na tablicy
   sprawdź datę odświeżenia i ewentualne braki dostępu.

Po wygaśnięciu tokenu odśwież sekret. Harmonogramy w publicznym repo GitHub może
wyłączyć po 60 dniach braku aktywności repozytorium — wtedy włącz workflow ponownie.
Nie ma automatycznego odnawiania tokenu ani gwarancji działania harmonogramu.

## Co trafia na tablicę

- Otwarte PR-y utworzone przez `dependabot[bot]`: aktualizacje wersji oraz poprawki
  bezpieczeństwa. Sam alert o podatności i naprawiający go PR to osobne pozycje.
- Otwarte alerty Dependabota, również klasyfikowane jako malware.
- Otwarte alerty CodeQL / code scanning.
- Otwarte alerty secret scanning: typ i link, **bez wartości sekretu**, fragmentów
  kodu, komentarzy ani lokalizacji z odpowiedzi API.
- Nieudane ostatnie zakończone, nieanulowane przebiegi aktywnych workflowów.
  Dla zwykłych workflowów śledzona jest gałąź domyślna, dla dynamicznych workflowów
  GitHuba ostatni przebieg na dowolnej gałęzi. To nie jest archiwum wszystkich
  historycznych błędów ani wszystkich checków PR. Sprawdzane jest ostatnich 20
  zakończonych przebiegów każdego workflowu, z pominięciem anulowanych/skipped/neutral.
- Karta z datą odświeżenia, liczbami oraz brakującymi uprawnieniami/funkcjami.

Repozytoria są odkrywane przy każdym uruchomieniu: wszystkie aktywne repo należące
do `ajsem1337`, również prywatne. Nowe repo dołączą automatycznie.
Monitoring nie włącza im skanerów ani nie dodaje konfiguracji Dependabota — to
osobne ustawienia. Funkcje niedostępne w darmowym planie pozostają niedostępne.
403/404 na karcie oznacza brak odczytu, a nie „zero podatności”. Nie ma tu
kopiowania zwykłych Issues, prywatnych zgłoszeń podatności ani alertów jakości
nieudostępnianych przez użyte API.

Pierwszy import obejmuje otwarte sprawy. Kolejne przebiegi aktualizują te same
wpisy i zachowują historię. Zamknięcie/naprawa w źródle ustawia „Gotowe”; ponowne
otwarcie przywraca „Do zrobienia”. Dla otwartych spraw zachowany jest ręczny status
pracy. Błąd odczytu nigdy sam nie zamyka sprawy. Gdy repo jest niedostępne,
archiwalne albo usunięte, zachowuje się ostatni znany stan. Ręczne zadania i już
obecne na tablicy PR-y pozostają pod ręczną kontrolą.

Alerty są prywatnymi szkicami projektu, a PR-y natywnymi pozycjami z linkiem do
źródła. Nie zmieniaj pola `ID monitora` ani znacznika w treści szkicu: identyfikują
wpis przy następnym odświeżeniu. Zmiany tytułu/treści zarządzanych szkiców zostaną
nadpisane; własne uwagi dopisuj w osobnym zadaniu.

Skrypt nie scala PR-ów, nie zmienia kodu/uprawnień, nie publikuje Issues ani
komentarzy i nie odrzuca alertów. Uruchamia się tylko z harmonogramu lub ręcznie,
bez dostępu do sekretu z workflowu PR. Publiczne logi zawierają wyłącznie liczby;
szczegóły i nazwy prywatnych repo pozostają w prywatnej tablicy. Jeśli tablica
zostanie upubliczniona, skrypt odmówi uruchomienia. Upublicznienie projektu samo
w sobie ujawni jednak istniejące wpisy — tablica powinna pozostać prywatna.

## Sprawdzenie lokalne

Wymagania: Python 3.10+, GitHub CLI (`gh`), zalogowane konto lub `GH_TOKEN`.

```bash
python3 -m unittest discover -s automation -p 'test_security_project_sync.py' -v
python3 automation/security_project_sync.py             # tylko podgląd, bez zapisu
python3 automation/security_project_sync.py --apply     # zapis do prywatnej tablicy
```

Dokumentacja GitHuba:
- https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/automating-projects-using-actions
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- https://docs.github.com/en/actions/administering-github-actions/usage-limits-billing-and-administration
- https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows

## AI assistance

**Made with AI.** This project was developed with AI assistance, including code, documentation, and testing.

