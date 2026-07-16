#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

docs_files=(README.md ARCHITECTURE.md SECURITY.md)
while IFS= read -r -d '' path; do
	docs_files+=("$path")
done < <(find docs integrations/terraform -type f \( -name '*.md' -o -name '*.html' -o -name '*.yml' \
	-o -name '*.yaml' -o -name '*.txt' -o -name '*.xml' \) -print0)

contract_files=(openapi/*.yaml)
failed=false

report_matches() {
	local label=$1
	local pattern=$2
	shift 2
	local matches
	matches=$(LC_ALL=C grep -Eni "$pattern" "$@" || true)
	if [[ -n $matches ]]; then
		printf 'docs consistency: %s\n%s\n' "$label" "$matches" >&2
		failed=true
	fi
}

# Product prose must describe capabilities, not bind the current documentation to
# a software release. API paths, profile/schema identifiers, and machine-readable
# OpenAPI info.version values remain legitimate contract identifiers.
report_matches \
	'product prose contains release-number branding; describe the capability without a release number' \
	"(Steward|Executor|Gateway|Relay)('s)?([[:space:]]+release)?[[:space:]]+[vV]?[0-9]+[.][0-9]+([.][0-9]+)?|[vV][0-9]+[.][0-9]+([.][0-9]+)?[[:space:]]+(compatibility|path|boundary|release|wedge|capabilit)" \
	"${docs_files[@]}" "${contract_files[@]}"

# Current guides and maintainer examples use RELEASE_TAG plus generic vX.Y.Z
# syntax. Keeping a real historical tag in live docs silently makes the site stale.
tag_matches=$(LC_ALL=C grep -En \
	'(^|[^[:alnum:]_])v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?([^[:alnum:]_]|$)' \
	"${docs_files[@]}" || true)
tag_matches=$(printf '%s\n' "$tag_matches" | grep -Fv 'v0.0.0-dev.<commit>' || true)
if [[ -n $tag_matches ]]; then
	printf '%s\n%s\n' \
		'docs consistency: current docs contain a concrete release tag; use RELEASE_TAG="<release-tag>" or vX.Y.Z' \
		"$tag_matches" >&2
	failed=true
fi

report_matches \
	'site configuration or layout reintroduced a release badge on every page' \
	'(^[[:space:]]*version:[[:space:]]*[0-9]|site[.]version)' \
	docs/_config.yml docs/_layouts/default.html

report_matches \
	'component counts are stale; the node package has seven binaries and three systemd services' \
	'((both|two)[[:space:]]+(Steward[[:space:]]+)?services|all[[:space:]]+three[[:space:]]+(binaries|entry[[:space:]]+points)|six([[:space:]]+[[:alnum:]_-]+){0,2}[[:space:]]+(binaries|entry[[:space:]]+points))' \
	"${docs_files[@]}"

# Removed commands and superseded current-file schemas are particularly dangerous
# in runbooks: they fail only after an operator has transferred authority or moved
# an artifact into an offline site. Historical prose may still explain receipt
# format 3, but live instructions must use the generic lifecycle client and the
# version-2 trust/bundle schemas.
report_matches \
	'documentation references the removed Hermes-specific task command; use stewardctl task submit/status/observe/wait' \
	'stewardctl[[:space:]]+hermes[[:space:]]+run' \
	"${docs_files[@]}"

report_matches \
	'documentation references a superseded service-task schema; use service-trust.v2 and task-bundle.v2' \
	'steward[.]((service-trust|task-bundle)[.]v1)' \
	"${docs_files[@]}"

report_matches \
	'documentation references the misleading removed lifecycle state; use failed_without_dispatch_evidence plus retry_safety' \
	'failed_before_dispatch' \
	"${docs_files[@]}" "${contract_files[@]}"

unrelated_product_pattern='rail''yard'
report_matches \
	'public Steward docs must not reference an unrelated product' \
	"$unrelated_product_pattern" \
	"${docs_files[@]}"

# Keep product claims concrete. These terms do not state a control, boundary, or
# measurable outcome and tend to hide the qualification a security reader needs.
report_matches \
	'product prose contains vague marketing language; name the concrete control or outcome instead' \
	'(best-in-class|world-class|enterprise-grade|production-grade|military-grade|cutting-edge|game-changing|future-proof|automagical|seamless(ly)?|revolutionary)' \
	"${docs_files[@]}"

report_matches \
	'documentation contains stray tool or XML wrapper markers' \
	'</?(content|invoke|tool|function)>' \
	"${docs_files[@]}"

report_matches \
	'CI job count is stale; the workflow has six required jobs' \
	'((three|five)[[:space:]]+(required[[:space:]]+)?CI[[:space:]]+jobs|with[[:space:]]+five[[:space:]]+jobs)' \
	"${docs_files[@]}"

if [[ $failed == true ]]; then
	exit 1
fi

printf 'docs consistency: evergreen prose, component counts, and task contracts OK\n'
