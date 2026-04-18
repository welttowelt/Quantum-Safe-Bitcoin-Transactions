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
- packages the current session into `qsb.zip` and launches the repo's Vast fleet runner for:
  - pinning
  - digest round 1 / round 2
- tracks fleet state and live status via:
  - `qsb_fleet_state.json`
  - `qsb_fleet_status.json`
- imports GPU hit files back into the session and resolves:
  - `sequence` / `locktime` from `pinning_hit.txt`
  - exact digest subset indices from `digest_hit.txt`
  - local result files are auto-ingested when the fleet runner writes them
- supports cloning a fully populated session to branch a demo or operator run
- explains the authorization path inside the UI:
  - static chain from `sig_nonce -> key_nonce -> sig_puzzle`
  - live mutation lab once `qsb_solution.json` exists
  - tests destination, qsb sequence, locktime, and helper-input mutations against the recovered puzzle chain
  - emits downloadable `binding_report.json` and `binding_report.html` artifacts for demos, notes, and partner threads
- carries a research layer next to the operator flow:
  - the coprocessing split: secure signer, untrusted GPU grinder, and on-chain verifier
  - a frontier lab comparing the published and repo-only profiles against the same 201-op / 10kb limits
  - what QSB keeps from Binohash and what it replaces
  - the three-layer map: QSB, zk-STARK recovery, and P2MR / BIP-360
  - live milestones and open public questions around the scheme
- surfaces the current operator tradeoffs in the UI:
  - relay / standardness
  - coverage limits
  - compatibility limits
  - emergency-cost posture
- renders the key artifacts inline:
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
- Vast orchestration expects the `vastai` CLI plus a configured API key (`VASTAI_API_KEY` or `~/.config/vastai/vast_api_key`).
- If the Studio process restarts mid-search, use `Sync Vast now` to refresh fleet state and pull down any hits that already landed.
