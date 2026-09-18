# xmip-core-authorize-opa

Authorization by a decision fetched from an Open Policy Agent over its REST data API, asked only where the node is online or the agent is on loopback; an agent that does not answer is a denial, never a permit. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
