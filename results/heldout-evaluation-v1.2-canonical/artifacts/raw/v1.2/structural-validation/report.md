# Held-Out Structural Validation

- Valid: `True`
- Git commit: `e6a17d330602db28363424b41acc6c94c8afb75b`
- Ground truth loaded: `False`
- Harness validation: `True`
- Health/reset only: `True`

## Target Checks

- `heldout-xss` health: status `200`, ok `True`
- `heldout-xss` reset: status `200`, ok `True`
- `heldout-idor` health: status `200`, ok `True`
- `heldout-idor` reset: status `200`, ok `True`
- `heldout-sqli` health: status `200`, ok `True`
- `heldout-sqli` reset: status `200`, ok `True`
