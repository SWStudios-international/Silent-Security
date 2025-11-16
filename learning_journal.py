import datetime

class LearningJournal:
    def __init__(self, filename):
        self.filename = filename

    def record(self, text):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {text}\n"
        with open(self.filename, "a", encoding="utf-8") as f:
            f.write(entry)

    def retrieve_entries(self, since=None):
        entries = []
        try:
            with open(self.filename, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    if not line:
                        continue  # skip blank lines

                    # sanity check: line must start with [YYYY...
                    if not (line.startswith("[") and "]" in line):
                        continue  # skip malformed logs

                    entry_header = line.split("]", 1)[0][1:]  # extract 2025-xx-xx...
                    try:
                        entry_time = datetime.datetime.strptime(entry_header, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        continue  # skip bad timestamps without dying

                    if since:
                        if entry_time >= since:
                            entries.append(line)
                    else:
                        entries.append(line)
        except FileNotFoundError:
            pass

        return entries
####Prototype v1.1####