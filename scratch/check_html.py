import re

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Let's check using node if installed
import subprocess
try:
    # Use npx @babel/cli or node to parse with esprima / babel if available
    res = subprocess.run(["node", "-e", "console.log('node is available')"], capture_output=True, text=True)
    print("Node:", res.stdout.strip())
except Exception as e:
    print("Node not available:", e)

# Test with node by extracting script
start = text.find('<script type="text/babel">') + len('<script type="text/babel">')
end = text.rfind('</script>')
script_content = text[start:end]

with open('scratch/extracted_script.js', 'w', encoding='utf-8') as f:
    f.write(script_content)

print(f"Extracted script: {len(script_content)} chars.")
