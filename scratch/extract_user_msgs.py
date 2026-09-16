import json

log_file = r"C:\Users\Prams\.gemini\antigravity-ide\brain\b49103fe-a97e-47dd-96ce-83e771281450\.system_generated\logs\transcript_full.jsonl"

with open(log_file, "r", encoding="utf-8") as f:
    for line in f:
        d = json.loads(line)
        if d.get("step_index") == 455:
            with open("scratch/last_user_request.txt", "w", encoding="utf-8") as out:
                out.write(d.get("content", ""))
            print("Wrote step 455 to scratch/last_user_request.txt")
            break
