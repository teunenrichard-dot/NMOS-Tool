# Nightly sweep reports

This directory is auto-populated by the **nightly-sweep** cron on
MasterPi (Raspberry Pi). Each morning at 03:00 Europe/Brussels the
sweep writes a fresh health-and-drift report for the whole Pi-projects
stack here, then git-commits and pushes.

- `latest.md` is a copy of the most recent report (always the same
  content as the dated file with today's date).
- `YYYY-MM-DD.md` is the dated archive of each day's report.

The companion **claude.ai Routine** reads `latest.md` from this repo
every morning at 09:00 Brussels and posts a conversational summary to
the chat list. That's why this repo has write access from the Pi —
not for the NMOS-Tool app itself.

See the workspace journal at `pi-projects/JOURNAL.md` (on the dev
machine) for the architecture rationale.
