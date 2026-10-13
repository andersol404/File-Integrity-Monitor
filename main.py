#!/usr/bin/env python3
# ============================================================
# Project: File Integrity Monitor
# Author: 0xander
# Watermark: created and maintained by 0xander
# Description: Detects unexpected file changes in monitored folders.
# Notes: Python + hashlib + pathlib + logging + professional output.
# ============================================================
"""File Integrity Monitor.

Monitoriza uma pasta e difere o estado atual com uma baseline de hashes
SHA-256. Quando um ficheiro é criado, removido ou alterado, gera um alerta
com data, hora e nome do ficheiro afetado.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ASCII_ART = r"""
   ___ _ _ _____ ___ ___ ___  _   _       __  __ _ _
  / __| (_)/ __|_ _| _ \ __| _ )| | | |___  \ \/ /| | |___ ___
 | (_ | | | (_ || ||   / _ \| _ \| |_| / -_)  >  < | |_| -_) -_)
  \___|_|_|\___|___|_|_\___/____/\___/\___| /_/\_\\___|___|___|
       0xander // file integrity monitor // cyber security
"""

WATERMARK = "0xander // file integrity monitor // baseline integrity watch"
BASE_DIR = Path(__file__).resolve().parent
MONITORED_DIR = BASE_DIR / "monitored"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_FILE = BASE_DIR / "events.log"


def utc_timestamp() -> str:
    """Retorna a data e hora atual em UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def setup_logger() -> logging.Logger:
    """Configura um logger profissional para stdout e ficheiro de eventos."""
    logger = logging.getLogger("fim")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def calculate_hash(file_path: Path) -> str:
    """Calcula o hash SHA-256 do conteúdo do ficheiro."""
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(directory: Path) -> dict[str, str]:
    """Percorre a pasta monitorizada e devolve os hashes por ficheiro."""
    snapshot: dict[str, str] = {}
    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file():
            rel_path = file_path.relative_to(directory).as_posix()
            snapshot[rel_path] = calculate_hash(file_path)
    return snapshot


def save_baseline(snapshot: dict[str, str]) -> None:
    """Guarda a baseline JSON fora da pasta monitorizada."""
    BASELINE_FILE.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_baseline() -> dict[str, str]:
    """Carrega a baseline JSON."""
    with BASELINE_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError("A baseline deve conter um dicionário em formato JSON.")
    return data


def compare_snapshots(current: dict[str, str], baseline: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    """Compara o estado atual com a baseline e devolve os eventos."""
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    modified: list[str] = []

    for relative_path in sorted(set(current) & set(baseline)):
        if current[relative_path] != baseline[relative_path]:
            modified.append(relative_path)

    return added, removed, modified


def initialize_baseline(force: bool = False) -> bool:
    """Cria a baseline inicial com hashes SHA-256 da pasta monitorizada."""
    MONITORED_DIR.mkdir(parents=True, exist_ok=True)

    if BASELINE_FILE.exists() and not force:
        print("[WARN] A baseline já existe. Usa --force para substituir a referência atual.")
        return False

    snapshot = scan_directory(MONITORED_DIR)
    save_baseline(snapshot)
    print(f"[OK] Baseline criada com {len(snapshot)} ficheiro(s) em {BASELINE_FILE}")
    return True


def check_integrity() -> tuple[list[str], list[str], list[str]]:
    """Compara a pasta monitorizada com a baseline atual."""
    if not BASELINE_FILE.exists():
        raise FileNotFoundError("Baseline não encontrada. Executa: python3 main.py init")

    baseline = load_baseline()
    current = scan_directory(MONITORED_DIR)
    return compare_snapshots(current, baseline)


def print_report(added: list[str], removed: list[str], modified: list[str]) -> None:
    """Apresenta os resultados da análise em formato amigável."""
    print("\n=== FILE INTEGRITY MONITOR ===")
    print(f"Timestamp: {utc_timestamp()}")
    print(f"Watermark: {WATERMARK}\n")

    if not added and not removed and not modified:
        print("[OK] Nenhuma alteração detetada.")
        return

    print("[ALERT] Alterações detetadas:\n")

    if added:
        print("-- Adicionados --")
        for name in added:
            print(f"  + {name}")

    if removed:
        print("\n-- Removidos --")
        for name in removed:
            print(f"  - {name}")

    if modified:
        print("\n-- Modificados --")
        for name in modified:
            print(f"  ~ {name}")

    print()


def run_monitor(interval: float = 5.0) -> None:
    """Executa monitorização contínua em ciclo."""
    logger = setup_logger()
    logger.info(ASCII_ART.strip())
    logger.info("%s | Monitor inicializado em %s", utc_timestamp(), MONITORED_DIR)

    if not BASELINE_FILE.exists():
        logger.warning("Baseline não encontrada. A criar uma referência inicial.")
        initialize_baseline(force=True)

    while True:
        try:
            added, removed, modified = check_integrity()
            if added or removed or modified:
                logger.warning("Alterações detetadas: %d adicionados, %d removidos, %d modificados.",
                               len(added), len(removed), len(modified))
                for name in added:
                    logger.warning("ADICIONADO: %s", name)
                for name in removed:
                    logger.warning("REMOVIDO: %s", name)
                for name in modified:
                    logger.warning("MODIFICADO: %s", name)
            else:
                logger.info("Sem alterações detetadas.")
            print_report(added, removed, modified)
            time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Monitor interrompido pelo utilizador.")
            print("\n[INFO] Monitor encerrado com sucesso.")
            break


def parse_args() -> argparse.Namespace:
    """Processa os argumentos da CLI."""
    parser = argparse.ArgumentParser(description="File Integrity Monitor em Python")
    parser.add_argument("command", nargs="?", choices=["init", "check", "watch"], default="check",
                        help="Comando: init cria a baseline, check compara e watch mantém monitorização contínua.")
    parser.add_argument("--force", action="store_true",
                        help="Substitui a baseline existente no comando init.")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Intervalo em segundos para o modo watch.")
    return parser.parse_args()


def main() -> int:
    """Função principal da aplicação."""
    args = parse_args()

    logger = setup_logger()
    logger.info(ASCII_ART.strip())
    logger.info("%s | Execução iniciada", utc_timestamp())

    try:
        if args.command == "init":
            initialize_baseline(force=args.force)
            return 0

        if args.command == "watch":
            run_monitor(interval=args.interval)
            return 0

        added, removed, modified = check_integrity()
        print_report(added, removed, modified)
        for name in added:
            logger.warning("ADICIONADO: %s", name)
        for name in removed:
            logger.warning("REMOVIDO: %s", name)
        for name in modified:
            logger.warning("MODIFICADO: %s", name)
        return 0
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        logger.error(str(exc))
        return 1
    except Exception as exc:  # pragma: no cover - camada defensiva
        print(f"[ERROR] Falha inesperada: {exc}")
        logger.exception("Erro crítico no monitor de integridade")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
