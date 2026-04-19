# QSB Studio

`QSB Studio` is the local browser UI for this repo. It runs the real pipeline commands, keeps each run in its own workspace, and keeps the operator and research views tied to the same artifacts.

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

## Operator flow

Studio shells out to the real repo commands:

- `setup`
- `export`
- `export-digest`
- `assemble`
- `test`
- `benchmark`

Each session gets its own workspace under `studio/sessions/`, so you can branch runs, keep artifacts separate, and clone a populated session before trying a different path.

## Remote search

Studio can package the current session into `qsb.zip` and hand it to the repo's Vast fleet runner for:

- pinning
- digest round 1
- digest round 2

It tracks:

- `qsb_fleet_state.json`
- `qsb_fleet_status.json`

It also imports hit files back into the workspace and resolves:

- `sequence` / `locktime` from `pinning_hit.txt`
- exact digest subset indices from `digest_hit.txt`

If the fleet runner writes local hit files after a restart, Studio auto-ingests them on the next refresh.

## Reports and research views

Studio keeps the research view next to the operator flow instead of in a separate note. It currently includes:

- a binding trace and mutation lab
- downloadable `binding_report.json` / `binding_report.html`
- a frontier lab with fit, reground, bottleneck, and runtime comparisons
- downloadable `frontier_report.json` / `frontier_report.html`
- the secure-signer / gpu-grinder / on-chain-verifier split
- QSB vs Binohash lineage
- the three-layer map: QSB, zk-STARK recovery, and P2MR / BIP-360
- current public milestones and open questions

## Artifacts

Studio renders the main workspace artifacts inline, including:

- `qsb_state.json`
- `gpu_pinning_params.json`
- `gpu_digest_r{1,2}_params.json`
- `qsb_solution.json`
- `qsb_raw_tx.hex`
- `benchmark_results.json`
- `pinning_import.json`
- `digest_r{1,2}_import.json`
- `qsb_vast_package.json`
- `qsb_fleet_state.json`
- `qsb_fleet_status.json`
- `binding_report.json`
- `binding_report.html`
- `frontier_report.json`
- `frontier_report.html`

## Notes

- Studio is local-first on purpose. It uses the repo's real Python entry points and keeps generated state inside the selected session workspace.
- `test` is the fastest way to validate the repaired flow without waiting for real GPU hits.
- This is an operator tool, not a wallet. Real CUDA search, real helper inputs, and real broadcast flows still depend on external infrastructure.
- Vast orchestration expects the `vastai` CLI plus a configured API key (`VASTAI_API_KEY` or `~/.config/vastai/vast_api_key`).
- If Studio restarts mid-search, use `Sync Vast now` to refresh fleet state and fetch any hits that already landed.
