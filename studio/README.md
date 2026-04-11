# QSB Studio

`QSB Studio` is a local-first operator UI for the repaired QSB repo. It wraps the real pipeline stages into a browser surface with isolated per-session workspaces.

## What it does

- creates dedicated workspaces under `studio/sessions/`
- runs the real pipeline commands in the background:
  - `setup`
  - `export`
  - `export-digest`
  - `assemble`
  - `test`
  - `benchmark`
- renders the key artifacts inline:
  - `qsb_state.json`
  - `gpu_pinning_params.json`
  - `gpu_digest_r{1,2}_params.json`
  - `qsb_solution.json`
  - `qsb_raw_tx.hex`
  - `benchmark_results.json`

## Run

From the repo root:

```bash
./.venv/bin/python -m studio.server
```

Then open:

```text
http://127.0.0.1:8421
```

To use another port:

```bash
QSB_STUDIO_PORT=9001 ./.venv/bin/python -m studio.server
```

## Notes

- The app is local-first on purpose. It shells out to the repo’s real Python entry points and keeps all generated state inside the chosen session workspace.
- `test` is the fastest way to validate the full repaired flow without waiting on real GPU hits.
- The UI is an operator surface, not a wallet. Real CUDA search, real helper inputs, and real broadcast flows still need external infrastructure.
