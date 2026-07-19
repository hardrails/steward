package steward.agent

default allow := false

allow if {
  input.placement.isolation == "hardened"
  input.runtime.engine in {"hermes", "openclaw"}
  startswith(input.runtime.image, "ghcr.io/")
}
