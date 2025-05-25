
# 🛡️ Cybersecurity Log Analyzer with GPT

**Projekt zaliczeniowy BECYB – Politechnika Warszawska**  
Zespół: Tomasz Lewiński, Aleksander Gajowniczek, Juliusz Kluge  
Temat: *Wykorzystanie ChatGPT do automatyzacji analizy zagrożeń*

---

## 📌 Opis projektu

Narzędzie wspomagające analizę zagrożeń w logach systemowych z wykorzystaniem modeli językowych (LLM). System wykorzystuje heurystyki oraz GPT-4 (OpenAI API), aby wspierać administratora w:

- identyfikacji potencjalnych ataków (XSS, SQLi, Brute Force itd.),
- generowaniu zaleceń reakcji,
- tworzeniu raportu w formacie Markdown,
- prezentowaniu wyników przez prosty frontend (Streamlit).

---

## 🧩 Architektura systemu

```
Logi Apache (.log)
    ↓
Log Parser (Regex)
    ↓
Heurystyka zagrożeń (Tagger)
    ↓
Grupowanie zdarzeń
    ↓
Formatowanie promptu
    ↓
🔗 Integracja z GPT-4 (OpenAI API)
    ↓
📄 Raport Markdown
    ↓
🖥️ Interfejs (Streamlit)
```

---

## 📁 Struktura repozytorium

```
.
├── main.py                 # Streamlit frontend
├── src/
│   ├── log_parser.py       # Parsowanie logów
│   ├── risk_analyzer.py    # Klasyfikacja zagrożeń
│   ├── batcher.py          # Grupowanie logów
├── .env.example           # Przykładowy plik z danymi API
├── threat_report.md       # Przykładowy raport wygenerowany przez system
├── docs/
│   ├── becyb_raport.pdf    # Raport projektu
│   ├── threat_report.pdf   # Konwersja z Markdown
├── requirements.txt       # Plik z wymaganymi pakietami pip
└── README.md              # Niniejszy plik

```

---

## 🛠️ Wymagania

- Python 3.9+
- API key do [OpenAI](https://platform.openai.com/account/api-keys)
- Pakiety: `streamlit`, `openai`, `python-dotenv`, `re`, `os`

Zainstaluj zależności:

```bash
pip install -r requirements.txt
```

---

## 🚀 Uruchomienie aplikacji

1. Utwórz plik `.env` na podstawie `.env.example`:

```env
OPENAI_API_KEY=sk-...
```

2. Uruchom frontend:

```bash
streamlit run main.py
```

3. Wgraj plik logów w formacie Apache i wygeneruj raport.

---

## 📎 Przykładowy wynik

Przykład analizy logu:

```
[27] <- (Numer linii logu) Cross-Site Scripting (XSS)
GET /search?q=<script>console.log('test')</script> 200 Ten log wskazuje na próbę ataku XSS poprzez wstrzyknięcie skryptu JS w parametrze zapytania. Zalecenia: Implementuj ochronę przed XSS poprzez użycie eskapowania znaków i walidację danych wejściowych.
```

Pełny raport znajduje się w pliku [`threat_report.md`](./threat_report.md).

---

## 🧠 Technologie

- **Język**: Python 3
- **AI**: OpenAI GPT-4
- **Frontend**: Streamlit
- **Parser logów**: regex + heurystyki
- **Export**: Markdown (raport zagrożeń)

---

## 📄 Licencja

Projekt edukacyjny, stworzony w ramach kursu BECYB. Do użytku niekomercyjnego.
