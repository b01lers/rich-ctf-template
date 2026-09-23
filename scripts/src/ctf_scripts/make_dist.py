#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import warnings
from io import StringIO
from pathlib import Path

import msgspec
from ruamel.yaml import YAML

from .common import Challenge, ComposeConfig

FAKE_FLAG = b"bctf{fake_flag}"


def matching_files(root: Path, pattern: str) -> set[Path]:
    try:
        paths = root.glob(pattern)
        files: set[Path] = set()
        for path in paths:
            if path.is_dir():
                files.update(child for child in path.rglob("*") if child.is_file())
            elif path.is_file():
                files.add(path)
        return files
    except (OSError, ValueError) as e:
        raise ValueError(f"invalid file pattern {pattern}") from e


def select_files(root: Path, rules: list[str]) -> list[Path]:
    selected: set[Path] = set()
    for rule in rules:
        exclude = rule.startswith("!")
        pattern = rule.removeprefix("!")
        if not pattern:
            raise ValueError("file pattern cannot be empty")
        matches = matching_files(root, pattern)
        if not exclude and not matches:
            warnings.warn(f"pattern matched no files: {rule}")
        if exclude:
            selected -= matches
        else:
            selected |= matches
    return sorted(selected)


def is_binary(contents: bytes) -> bool:
    if b"\0" in contents:
        return True
    try:
        contents.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def copy_file(source: Path, destination: Path, real_flag: bytes) -> None:
    contents = source.read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if is_binary(contents):
        shutil.copy(source, destination)
        print(f"Skipped flag replacement for binary file: {source}")
        if real_flag in contents:
            warnings.warn(f"real flag found in binary file: {source}")
    else:
        replacements = contents.count(real_flag)
        destination.write_bytes(contents.replace(real_flag, FAKE_FLAG))
        shutil.copymode(source, destination)
        if replacements:
            print(f"Replaced {replacements} flag occurrence(s) in {source}")


def render_compose(challenge: Path, settings: ComposeConfig) -> str:
    source = challenge / settings.file
    yaml = YAML()
    yaml.preserve_quotes = True
    compose = yaml.load(source)
    if not isinstance(compose, dict):
        raise TypeError(f"{settings.file} must contain a mapping")
    services = compose.get("services")
    if not isinstance(services, dict):
        raise TypeError(f"{settings.file} must contain a services mapping")

    missing = set(settings.services) - services.keys()
    if missing:
        raise ValueError(f"services not found in {settings.file}: {', '.join(sorted(missing))}")
    for name in list(services):
        if name not in settings.services:
            del services[name]

    output = StringIO()
    yaml.dump(compose, output)
    return output.getvalue()


def make_distribution(challenge: Path) -> None:
    metadata = msgspec.json.decode((challenge / "chal.json").read_bytes(), type=Challenge)
    config = metadata.distribution
    if config is None:
        raise ValueError("chal.json does not contain distribution configuration")
    real_flag = metadata.flag
    build_sh = challenge / "build.sh"
    if build_sh.exists():
        subprocess.run([build_sh], check=True)

    source = challenge / "src"
    selected = select_files(source, config.files)

    dist = challenge / "dist"
    if dist.exists():
        warnings.warn(f"Overwriting {dist}")
        shutil.rmtree(dist)
    dist.mkdir()

    for path in selected:
        copy_file(path, dist / path.relative_to(source), real_flag.encode())

    if config.compose is not None:
        compose = render_compose(challenge, config.compose)
        replacements = compose.count(real_flag)
        (dist / "docker-compose.yml").write_text(compose.replace(real_flag, FAKE_FLAG.decode()))
        if replacements:
            print(f"Replaced {replacements} flag occurrence(s) in docker-compose.yml")

    print(f"Copied {len(selected) + (config.compose is not None)} file(s) to {dist}")


class Arguments(argparse.Namespace):
    challenge: Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Copy challenge distribution files")
    parser.add_argument("challenge", nargs="?", default=Path(), type=Path)
    args = parser.parse_args(namespace=Arguments())
    make_distribution(args.challenge.resolve())


if __name__ == "__main__":
    main()
