# 🛡️ Raport zagrożeń (heurystyki + analiza GPT)

## 🔍 Wykryte podejrzane logi (heurystyki):

- **[linie: 4, 5, 6]** `3x POST /login 401 z IP 192.168.1.13` → **Brute Force (grupowane)**
- **[2]** `GET /search?q=<script>alert('xss')</script> 200` → **XSS**
- **[7]** `GET /../../../../etc/passwd 403` → **Directory Traversal**
- **[8]** `GET /admin/config.php 404` → **Reconnaissance**
- **[9]** `GET /index.php?cmd=ls%20-la 200` → **Command Injection**
- **[20]** `GET /file?name=../../../config.ini 403` → **Directory Traversal**
- **[22]** `GET /uploads/../../secret.txt 403` → **Directory Traversal**
- **[27]** `GET /search?q=<script>console.log('test')</script> 200` → **XSS**
- **[49]** `GET /admin 403` → **Reconnaissance**
- **[81]** `GET /admin/panel 403` → **Reconnaissance**
- **[82]** `GET /config.php 404` → **Reconnaissance**

## 🤖 Analiza przez GPT-4:

### [4] Brute Force Attack
`POST /login 401 (Wystąpiło 3 razy w godzinach: 12:03, 12:03, 12:03)`
Ten log wskazuje na nieudane próby logowania, co może sugerować atak typu brute force.
**Zalecenia:** Wdrożyć blokowanie konta po wielokrotnych nieudanych próbach logowania i rozważ użycie CAPTCHA.

### [2] Cross-Site Scripting (XSS)
`GET /search?q=<script>alert('xss')</script> 200`
Wpis wskazuje na próbę XSS przy użyciu tagu `<script>`. Takie działanie może prowadzić do kradzieży sesji użytkowników.
**Zalecenia:** Zastosować zestaw nagłówków Content Security Policy (CSP) oraz walidację i sanitację danych wejściowych.

### [7] Directory Traversal
`GET /../../../../etc/passwd 403`
Ten log wskazuje na próbę ataku Directory Traversal, próbując uzyskać dostęp do plików systemowych.
**Zalecenia:** Ograniczyć dostęp do zasobów serwera przez upewnienie się, że serwer nie interpretuje sekwencji ../ jako przejście do katalogu nadrzędnego, oraz zastosować mechanizmy kontroli dostępu.

### [8] Nie wykryto zagrożenia
`GET /admin/config.php 404`
Ten wpis wskazuje na próbę uzyskania dostępu do pliku, który nie istnieje na serwerze. Może być to skanowanie w poszukiwaniu luk bezpieczeństwa.
**Zalecenia:** Monitorować logi pod kątem podobnych prób, by wykluczyć skanowanie w poszukiwaniu wrażliwych plików.

### [9] Command Injection
`GET /index.php?cmd=ls%20-la 200`
Log wskazuje na próbę wykonania ataku Command Injection, co może prowadzić do nieautoryzowanego dostępu do systemu.
**Zalecenia:** Uniemożliwić bezpośrednie przekazywanie danych wejściowych do powłoki systemowej oraz stosować escaped input i kontekstowe enkodowanie.

### [20] Directory Traversal
`GET /file?name=../../../config.ini 403`
Wpis wskazuje na próbę ataku Directory Traversal, próbując uzyskać dostęp do potencjalnie wrażliwych plików konfiguracyjnych.
**Zalecenia:** Zabezpieczyć aplikację przez walidację ścieżek i upewnić się, że serwer obsługuje żądania z poprawną kontrolą dostępu.

### [22] Directory Traversal
`GET /uploads/../../secret.txt 403`
Podobnie jak poprzednie, ten log wskazuje na próbę ataku Directory Traversal, dążąc do wyciągnięcia poufnych danych.
**Zalecenia:** Wzmocnić mechanizmy kontroli dostępu oraz walidację ścieżek plików w aplikacji.

### [27] Cross-Site Scripting (XSS)
`GET /search?q=<script>console.log('test')</script> 200`
To również jest próba ataku XSS, choć mniej szkodliwa, pokazując lukę w umożliwieniu wykonania kodu JavaScript.
**Zalecenia:** Podobnie jak przy innym ataku XSS, wdrożyć Content Security Policy (CSP) i dokładną walidację oraz sanitację danych wejściowych.

### [49] Nie wykryto zagrożenia
`GET /admin 403`
Wpis wskazuje na próbę dostępu do panelu administracyjnego, jednak użytkownik nie posiada wystarczających uprawnień.
**Zalecenia:** Upewnić się, że dostęp do panelu administracyjnego jest zabezpieczony poprzez dodatkowe środki autoryzacji oraz ograniczyć dostęp do zaufanych adresów IP.

### [81] Nie wykryto zagrożenia
`GET /admin/panel 403`
Podobnie jak poprzednio, oznacza próbę dostępu do strony admina przez nieautoryzowanego użytkownika.
**Zalecenia:** Zachować monitorowanie tych prób, aby wykryć możliwe skanowanie pod względem wykrywania potencjalnych luk.

### [82] Nie wykryto zagrożenia
`GET /config.php 404`
Log wskazuje na próbę dostępu do pliku, który nie istnieje. To może sugerować skanowanie w poszukiwaniu problematycznych plików konfiguracyjnych.
**Zalecenia:** Kontynuować monitorowanie logów pod kątem podobnych żądań i zastosować ochronę poprzez reguły firewall.