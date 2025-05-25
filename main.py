import os
import tempfile
from collections import defaultdict
from dotenv import load_dotenv
import streamlit as st
from openai import OpenAI

# Importy własnych modułów (upewnij się, że struktura katalogów jest poprawna)
from src.log_parser import parse_log_file
from src.risk_analyzer import tag_logs_with_risk
from src.batcher import batch_logs

# Ładowanie konfiguracji z pliku .env (jeśli istnieje)
load_dotenv()

# Funkcja grupująca logi typu brute force
def group_similar_risks(logs):
    grouped = defaultdict(list)
    for i, log in enumerate(logs):
        if log['risk'] == "Possible Brute Force":
            key = (log['ip'], log['method'], log['path'], log['status'])
            grouped[key].append((i + 1, log))  # zapis numeru linii i wpisu

    grouped_entries = []
    used_lines = set()

    for (ip, method, path, status), entries in grouped.items():
        if len(entries) >= 3:
            line_numbers = [idx for idx, _ in entries]
            # Załóżmy, że daty są rozdzielone dwukropkami; pobieramy godziny i minuty
            timestamps = [":".join(log['datetime'].split(":")[1:3]) for _, log in entries]
            sample_log = entries[0][1]
            grouped_entries.append({
                "lines": line_numbers,
                "risk": "Brute Force (grupowane)",
                "summary": f"{len(entries)}x {method} {path} {status} z IP {ip}",
                "original": sample_log,
                "line": line_numbers[0],
                "count": len(entries),
                "timestamps": timestamps
            })
            used_lines.update(line_numbers)

    return grouped_entries, used_lines

# Funkcja formatująca prompt do analizy przez GPT
def format_prompt(logs):
    prompt = (
        "Poniżej znajduje się lista podejrzanych wpisów z logu serwera Apache. "
        "Dla każdego z nich wykonaj **krótką, profesjonalną analizę** w formacie Markdown.\n\n"
        "Dla każdego logu:\n"
        "- Określ typ ataku (np. SQL Injection, XSS, Directory Traversal, itp.) – jeśli dotyczy\n"
        "- Wyjaśnij, na czym polega zagrożenie\n"
        "- Zaproponuj jedno lub dwa konkretne działania dla administratora\n\n"
        "Jeśli dany log **nie zawiera zagrożenia**, napisz w odpowiedzi:\n"
        "`Nie wykryto zagrożenia: (wyjaśnienie co oznacza wpis)`\n\n"
        "### Format odpowiedzi:\n"
        "### [12] SQL Injection\n"
        "`GET /products.php?id=1' OR '1'='1 200`\n"
        "Ten log zawiera próbę SQL Injection przy użyciu operatora OR. Może umożliwić dostęp do bazy danych.\n"
        "**Zalecenia:** Wprowadzić parametryzację zapytań SQL i walidację danych wejściowych.\n\n"
        "### Logi do analizy:\n"
    )
    for log in logs:
        line = log['line']
        details = f"{log['method']} {log['path']} {log['status']}"
        if log.get("extra"):
            details += f" {log['extra']}"
        prompt += f"{line}. {details}\n"
    return prompt

# Funkcja wysyłająca prompt do OpenAI i zbierająca odpowiedzi
def analyze_logs_with_openai(client, logs):
    if not logs:
        return "Brak podejrzanych logów do analizy."

    batched = list(batch_logs(logs, batch_size=20))
    all_responses = []

    try:
        for batch in batched:
            prompt = format_prompt(batch)
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content":
                        "Jesteś ekspertem ds. cyberbezpieczeństwa. Twoim zadaniem jest analiza logów serwera Apache. "
                        "Zwróć wynik w dokładnie określonym formacie Markdown, zgodnie z poleceniem użytkownika. "
                        "Nie dodawaj żadnych wstępów ani podsumowań."},
                    {"role": "user", "content": prompt}
                ]
            )
            all_responses.append(response.choices[0].message.content.strip())
    except Exception as e:
        return f"❌ Błąd API OpenAI: {str(e)}"

    return "\n\n".join(all_responses)

# Funkcja główna wykonująca analizę logów i generująca raport
def run_analysis(log_file_path, client):
    # Wczytywanie oraz przetwarzanie logów
    parsed_logs = parse_log_file(log_file_path)
    tagged_logs = tag_logs_with_risk(parsed_logs)

    # Grupowanie wpisów typu brute force
    grouped_brute, used_lines = group_similar_risks(tagged_logs)

    # Wybór logów, które nie należą do zgrupowanych
    flat_logs = []
    for i, log in enumerate(tagged_logs, 1):
        if log['risk'] != "OK" and i not in used_lines:
            flat_logs.append({
                "line": i,
                "method": log["method"],
                "path": log["path"],
                "status": log["status"],
                "extra": ""
            })

    # Dodanie zgrupowanych logów jako reprezentatywnych do analizy GPT
    logs_for_gpt = []
    for group in grouped_brute:
        logs_for_gpt.append({
            "line": group["line"],
            "method": group["original"]["method"],
            "path": group["original"]["path"],
            "status": group["original"]["status"],
            "extra": f"(Wystąpiło {group['count']} razy w godzinach: {', '.join(group['timestamps'])})"
        })
    logs_for_gpt.extend(flat_logs)

    # Budowanie raportu
    report_lines = ["# 🛡️ Raport zagrożeń (heurystyki + analiza GPT)\n"]

    if not (flat_logs or grouped_brute):
        report_lines.append("✅ Brak podejrzanych logów wykrytych przez heurystyki.\n")
    else:
        report_lines.append("## 🔍 Wykryte podejrzane logi (heurystyki):\n")
        for group in grouped_brute:
            lines_str = ", ".join(map(str, group["lines"]))
            report_lines.append(f"- **[linie: {lines_str}]** `{group['summary']}` → **{group['risk']}**")

        for i, log in enumerate(tagged_logs, 1):
            if log['risk'] != "OK" and i not in used_lines:
                report_lines.append(f"- **[{i}]** `{log['method']} {log['path']} {log['status']}` → **{log['risk']}**")

        report_lines.append("\n## 🤖 Analiza przez GPT-4:\n")
        gpt_output = analyze_logs_with_openai(client, logs_for_gpt)
        report_lines.append(gpt_output)

    return "\n".join(report_lines)

# Konfiguracja aplikacji Streamlit
st.title("Analiza Logów Serwera")
st.write("Prześlij plik z logami lub skorzystaj z domyślnego pliku, aby przeprowadzić analizę zagrożeń.")

# Opcja wyboru źródła pliku logów
log_source = st.radio(
    "Źródło logów:",
    ("Domyślny plik", "Wgraj plik"),
    index=0
)

tmp_file_path = None

if log_source == "Domyślny plik":
    default_path = os.path.join("data", "synthetic_apache.log")
    if os.path.exists(default_path):
        tmp_file_path = default_path
        st.info(f"Używany domyślny plik logów: {default_path}")
    else:
        st.error(f"Domyślny plik nie został znaleziony pod ścieżką: {default_path}")
else:
    uploaded_file = st.file_uploader("Wybierz plik z logami (.log lub .txt)", type=["log", "txt"])
    if uploaded_file is not None:
        # Zapisujemy przesłany plik do tymczasowego pliku
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_file_path = tmp_file.name
        st.success("Plik został wczytany pomyślnie.")

# Obsługa klucza API – próba pobrania z pliku .env lub ręczne wprowadzenie
api_key = os.getenv("OPENAI_API_KEY") or st.text_input("Wprowadź klucz API OpenAI", type="password")
if not api_key:
    st.error("Klucz API OpenAI nie jest ustawiony. Uzupełnij pole powyżej.")
    st.stop()

# Inicjalizacja klienta OpenAI
client = OpenAI(api_key=api_key)

# Przycisk do uruchomienia analizy
if tmp_file_path:
    if st.button("Analizuj logi"):
        with st.spinner("Przetwarzanie logów i generowanie raportu..."):
            report = run_analysis(tmp_file_path, client)
        st.markdown(report)
        st.download_button(
            label="Pobierz raport",
            data=report,
            file_name="threat_report.md",
            mime="text/markdown"
        )
else:
    st.info("Proszę wybrać źródło logów, aby rozpocząć analizę.")
