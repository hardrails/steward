# Hermes Agent feasibility adapter

This directory contains Steward's independently maintained feasibility adapter for
Hermes Agent. It is not an upstream image and it is not a claim that arbitrary
Hermes releases work under Steward.

The build consumes an already-present checkout of the exact upstream revision
recorded in `adapter.json`. `scripts/hermes-feasibility.sh` exports that checkout
with `git archive`, builds the adapter, and then runs the hostile-runtime checks.
The build never uses the upstream image: that image starts as root, declares a
volume, and its Dockerfile at the selected revision names two lockfiles that are
not present in the tree.

The adapter replaces upstream's root-only s6 initialization with `entrypoint.py`.
That shim performs only fixed-path, non-root initialization, verifies and installs
the signed fixture skill, exposes side-effect-free negotiation, and starts the
upstream gateway. It does not change Hermes core source.

Passing this feasibility gate proves only the capabilities enumerated in the
generated evidence. Full release qualification still requires the later
conformance, recovery, channel, quota, and Gateway-grant tests.
