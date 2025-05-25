def batch_logs(logs, batch_size=20):
    for i in range(0, len(logs), batch_size):
        yield logs[i:i + batch_size]