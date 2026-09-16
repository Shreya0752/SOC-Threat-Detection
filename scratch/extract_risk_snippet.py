import re

html = open("frontend/index.html", "r", encoding="utf-8").read()

# Find where 'risk-intelligence' is handled
pos = html.find("risk-intelligence")
print(f"Found risk-intelligence at pos: {pos}")

# Extract 4000 characters around it
snippet = html[pos:pos+6000]
with open("scratch/risk_snippet.txt", "w", encoding="utf-8") as f:
    f.write(snippet)
print("Wrote snippet to scratch/risk_snippet.txt")
