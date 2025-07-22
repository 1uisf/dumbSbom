import json

# Input and output file paths
INPUT_FILE = 'pipfileDummy_raw.json'
OUTPUT_FILE = 'pipfileDummy.json'

# Read the raw escaped JSON string
with open(INPUT_FILE, 'r', encoding='utf-8') as f:
    raw = f.read().strip()

# Unescape the string
unescaped = raw.encode('utf-8').decode('unicode_escape')

# Parse the JSON
parsed = json.loads(unescaped)

# Write pretty-printed JSON to output file
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    json.dump(parsed, f, indent=2)

print(f"Pretty-printed JSON written to {OUTPUT_FILE}") 