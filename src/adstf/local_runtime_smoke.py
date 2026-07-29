from __future__ import annotations

import argparse
from pathlib import Path

from adstf.local_runtime import MODEL_ROOT, OUTPUT_ROOT, RUNTIME_ROOT, run_smoke_package


def default_runtime_executable() -> Path:
    return RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run non-scored local llama.cpp model smoke validation.")
    parser.add_argument("--runtime-exe", type=Path, default=default_runtime_executable())
    parser.add_argument("--model-root", type=Path, default=MODEL_ROOT)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()
    package = run_smoke_package(executable=args.runtime_exe, model_root=args.model_root, output_root=args.output_root)
    if not package["validation"]["valid"]:
        raise SystemExit(f"local runtime smoke validation failed: {package['validation']['errors']}")
    print(f"Local runtime smoke artifacts written to: {args.output_root}")


if __name__ == "__main__":
    main()
