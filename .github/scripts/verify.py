from pathlib import Path 
from json import loads, JSONDecodeError

violations = 0

context_dir = Path(".") / "src"
for dir in context_dir.iterdir():
    if dir.is_dir() and dir.name in ["rev", "web", "pwn", "misc", "blockchain", "osint", "crypto"]:
        for challenge in dir.iterdir():
            try:
                chal_json = loads((challenge / "chal.json").read_text())
                chal_json["name"]
                chal_json["author"]
                chal_json["flag"]
                chal_json["description"]
            except FileNotFoundError as e:
                violations += 1
                print(f"** {violations} Could not find chal.json inside challenge {dir.name}/{challenge.name}")
            except (JSONDecodeError, KeyError) as e:
                violations += 1
                print(f"** {violations} malformed chall.json inside challenge {dir.name}/{challenge.name}")

if violations > 0:
    exit(1)


print("Commenting out ports in docker-compose.yml ")

files = list(context_dir.rglob("docker-compose.yml"))

for file in files:
    lines = file.read_text().split("\n")

    updated_lines = []
    inside_ports = False
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("ports:"):
            updated_lines.append("# " + line)
            inside_ports = True
        elif inside_ports and (stripped.startswith("-") or stripped.startswith("  -")):
            updated_lines.append("# " + line)
        else:
            inside_ports = False
            updated_lines.append(line)

        file.write_text("\n".join(updated_lines))

print("Done!")