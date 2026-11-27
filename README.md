# xmip-core-authorize-opa

Authorization by a decision fetched from an Open Policy Agent over its REST data API, asked only where the node declares the Node capability `online` (ADR-0056, amendment 2026-11-24) or the agent is on loopback; an agent that is not asked, or does not answer, is a denial, never a permit and never an abstention. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

The agent is connected to through `net::connect`, the estate's one TCP connect.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
