# ChainPwn

Orchestrates existing Kali tools into a single IP → root chain.

## Install

```bash
msfrpcd -P msf -S -a 127.0.0.1 -p 55553 &
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
chainpwn run 10.10.10.10 --preset normal
chainpwn run http://box.htb --profile web --preset deep
chainpwn run 10.10.10.10 -p deep --no-msf
chainpwn resume loot/state_abc123.json
chainpwn report loot/
```

Or run without installing:

```bash
cd chainpwn && python chainpwn.py run 10.10.10.10
```

## Wordlists

`config/wordlists.yaml` defines every fuzzing stage (`dir`, `vhost`,
`subdomain`, `param`, `user`, `pass`). Each stage accepts **multiple**
wordlists with per-list `path`, `priority`, `threads`, `enabled` and
`append_extension`. Presets (`quick` / `normal` / `deep`) pick which
lists to use and how to combine them via `strategy`:

- `sequential` — run each list one after another
- `parallel`   — run all enabled lists concurrently, merge results
- `merge`      — concatenate + dedup all lists into one run
- `fallback`   — run by priority; stop at first list with hits
