# v1.3 Figure Output Conventions

Template status: convention only. No experiment results are recorded in this
file.

Each thesis figure generated for v1.3 should be stored in all applicable forms:

- `figures/<figure-id>.png` for quick viewing
- `figures/<figure-id>.pdf` for thesis inclusion
- `figures/<figure-id>.json` for machine-readable source data
- `figures/<figure-id>.csv` when the figure is table-derived

Each figure source file must include or reference:

- study ID
- protocol version
- generated timestamp
- source artifact paths
- source artifact SHA-256 values
- metric definitions used
- undefined-value handling

Figures must not be generated from manually edited chart values.
