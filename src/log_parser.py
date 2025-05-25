import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)(?: HTTP/\d\.\d)?" (?P<status>\d{3}) (?P<size>\d+)'
)

def parse_log_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

def parse_log_file(file_path):
    parsed_logs = []
    with open(file_path, 'r') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)
    return parsed_logs