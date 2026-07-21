package steward.agent

default allow := false

allow if {
  input.placement.isolation == "hardened"
  input.runtime.engine == "hermes"
  startswith(input.runtime.image, "ghcr.io/")
}
