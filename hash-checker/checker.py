"""Generador/verificador de hashes para revisar la integridad de archivos.

Uso:
    python3 checker.py hash archivo.zip
    python3 checker.py hash "*.txt" -o checksums.txt          # patrón ENTRE COMILLAS
    python3 checker.py hash pruebas -o checksums.txt          # carpeta (sin subcarpetas)
    python3 checker.py hash pruebas -r -o checksums.txt       # carpeta + subcarpetas
    python3 checker.py verify checksums.txt

'verify' reporta: sin cambios, modificados, eliminados, nuevos y duplicados.
"""

import argparse
import glob
import hashlib
import os
import sys
from collections import defaultdict
from pathlib import Path

CHUNK_SIZE = 65536
IGNORED_NAMES = {".DS_Store", "Thumbs.db", "__pycache__", ".git"}
CHECKSUMS_PREFIX = "checksums"


def hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def is_ignored(name: str) -> bool:
    return name in IGNORED_NAMES or name.startswith(CHECKSUMS_PREFIX)


def expand_source(source: str, recursive: bool) -> list:
    path = Path(source)

    if path.is_dir():
        if recursive:
            found = []
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not is_ignored(d))
                found += [Path(root) / n for n in sorted(files) if not is_ignored(n)]
            return found
        return sorted(p for p in path.iterdir()
                      if p.is_file() and not is_ignored(p.name))

    if any(c in source for c in "*?["):
        matches = (Path(p) for p in glob.glob(source, recursive=True))
        return sorted(p for p in matches if p.is_file() and not is_ignored(p.name))

    return [path]


def collect_files(sources, recursive: bool, skip=None) -> list:
    files, seen = [], set()
    for source in sources:
        for path in expand_source(source, recursive):
            key = path.resolve()
            if key in seen or key == skip:
                continue
            seen.add(key)
            files.append(path)
    return files


def print_duplicates(digests: dict) -> int:
    groups = defaultdict(list)
    for name, digest in digests.items():
        groups[digest].append(name)
    duplicates = [names for names in groups.values() if len(names) > 1]

    for number, names in enumerate(duplicates, 1):
        print(f"[=] DUPLICADOS (grupo {number}, mismo contenido):")
        for name in names:
            print(f"      {name}")
    return len(duplicates)


def cmd_hash(args) -> int:
    skip = Path(args.output).resolve() if args.output else None
    digests = {}
    had_error = False

    for path in collect_files(args.files, args.recursive, skip):
        if not path.is_file():
            print(f"[!] No es un archivo: {path}", file=sys.stderr)
            had_error = True
            continue
        try:
            digest = hash_file(path, args.algorithm)
        except OSError as e:
            print(f"[!] No se pudo leer {path}: {e.strerror}", file=sys.stderr)
            had_error = True
            continue
        digests[path.as_posix()] = digest
        print(f"{digest}  {path.as_posix()}")

    if not digests:
        print("[!] No se encontró ningún archivo.", file=sys.stderr)
        return 1

    print()
    duplicate_groups = print_duplicates(digests)
    print(f"[+] {len(digests)} archivos, {duplicate_groups} grupos de duplicados")

    if args.output:
        lines = [f"# algoritmo={args.algorithm}",
                 f"# recursivo={'si' if args.recursive else 'no'}"]
        lines += [f"# fuente={source}" for source in args.files]
        lines += [f"{digest}  {name}" for name, digest in digests.items()]
        Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[+] Guardado en {args.output}")
    return 1 if had_error else 0


def parse_checksums(path: Path, default_algorithm: str):
    algorithm, recursive, sources, entries = default_algorithm, False, [], {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            key, _, value = line[1:].partition("=")
            key, value = key.strip(), value.strip()
            if key == "algoritmo":
                algorithm = value
            elif key == "recursivo":
                recursive = value == "si"
            elif key == "fuente":
                sources.append(value)
            continue
        expected, _, filename = line.partition("  ")
        entries[filename] = expected

    return algorithm, recursive, sources, entries


def cmd_verify(args) -> int:
    checksum_path = Path(args.checksums)
    if not checksum_path.exists():
        print(f"[!] No existe: {checksum_path}", file=sys.stderr)
        return 1

    algorithm, recursive, sources, entries = parse_checksums(checksum_path, args.algorithm)
    digests = {}
    ok = modified = deleted = new = 0

    for filename, expected in entries.items():
        target = Path(filename)
        if not target.is_file():
            print(f"[!] ELIMINADO   {filename}")
            deleted += 1
            continue
        try:
            actual = hash_file(target, algorithm)
        except OSError:
            print(f"[!] ILEGIBLE    {filename}")
            modified += 1
            continue
        digests[filename] = actual
        if actual == expected:
            print(f"[OK]            {filename}")
            ok += 1
        else:
            print(f"[!] MODIFICADO  {filename}")
            modified += 1

    if sources:
        for path in collect_files(sources, recursive, skip=checksum_path.resolve()):
            name = path.as_posix()
            if name in entries:
                continue
            try:
                digests[name] = hash_file(path, algorithm)
            except OSError:
                continue
            print(f"[+] NUEVO       {name}")
            new += 1
    else:
        print("[i] Este checksums.txt no guarda sus fuentes: no se buscan archivos "
              "nuevos. Vuelve a generarlo con 'hash -o'.")

    print()
    duplicate_groups = print_duplicates(digests)

    print(f"\n[+] {ok} sin cambios, {modified} modificados, {deleted} eliminados, "
          f"{new} nuevos, {duplicate_groups} grupos de duplicados")
    return 1 if (modified or deleted or new) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="calcular hashes de archivos")
    p_hash.add_argument("files", nargs="+",
                        help='archivo(s), carpeta(s) o patrón entre comillas, ej: "*.txt"')
    p_hash.add_argument("-a", "--algorithm", default="sha256",
                        choices=sorted(hashlib.algorithms_guaranteed))
    p_hash.add_argument("-o", "--output", help="guardar resultado en este archivo")
    p_hash.add_argument("-r", "--recursive", action="store_true",
                        help="al recibir una carpeta, incluir también sus subcarpetas")
    p_hash.set_defaults(func=cmd_hash)

    p_verify = sub.add_parser("verify", help="comparar archivos contra un checksums.txt")
    p_verify.add_argument("checksums", help="archivo generado con 'hash -o'")
    p_verify.add_argument("-a", "--algorithm", default="sha256",
                          help="se usa solo si el archivo no trae cabecera #algoritmo=")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())