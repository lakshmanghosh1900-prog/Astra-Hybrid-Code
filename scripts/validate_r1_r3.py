import json
from pathlib import Path
from jsonschema import Draft202012Validator

REPO = Path(r"C:\Users\User\Desktop\ASTRA CODER")
PAIRS = [
    ("authorization.json", "docs/schemas/authorization.schema.json"),
    ("license-check.json", "docs/schemas/license-check.schema.json"),
    ("rea-input-manifest.json", "docs/schemas/rea-input-manifest.schema.json"),
]

failed = False
for data_file, schema_file in PAIRS:
    data = json.loads((REPO / data_file).read_text(encoding="utf-8"))
    schema = json.loads((REPO / schema_file).read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(data))
    if errors:
        failed = True
        print(f"INVALID: {data_file} ({len(errors)} errors)")
        for e in errors[:5]:
            print(f"  - {e.message}")
    else:
        print(f"VALID: {data_file}")

exit(1 if failed else 0)
