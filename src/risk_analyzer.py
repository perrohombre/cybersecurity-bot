import re


def classify_risk(entry):
    path = entry.get('path', "").lower()
    method = entry.get('method', "").upper()
    status = entry.get('status', "")

    if re.search(r"(union|select|'\s?or\s?')", path):
        return "SQL Injection"
    if "<script" in path or "onerror=" in path:
        return "XSS"
    if "../" in path:
        return "Directory Traversal"
    if any(cmd in path for cmd in [";", "cmd=", "|"]):
        return "Command Injection"
    if "/admin" in path or "config.php" in path:
        return "Reconnaissance"
    if method == "POST" and "/login" in path and status == "401":
        return "Possible Brute Force"

    return None


def tag_logs_with_risk(logs):
    tagged_logs = []
    for entry in logs:
        risk = classify_risk(entry)
        entry['risk'] = risk if risk is not None else "OK"
        tagged_logs.append(entry)
    return tagged_logs