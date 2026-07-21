#!/usr/bin/env bash
# Prove that every shipped node root helper enters Bash privileged mode before
# it can consume caller-controlled startup files or exported functions.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-privileged-shell-test.XXXXXX")
cleanup() {
	unset -f echo 2>/dev/null || true
	rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

root_helpers=(
	scripts/install-steward.sh
	scripts/install-node.sh
	scripts/configure-node.sh
	scripts/configure-admission.sh
	scripts/node-preflight.sh
	scripts/activate-node-release.sh
	scripts/uninstall-node.sh
	scripts/node-removal-guard.sh
	scripts/build-relay-image.sh
	scripts/preprovision-feasibility-handle.sh
	scripts/node-doctor.sh
)
for relative in "${root_helpers[@]}"; do
	read -r shebang <"$root/$relative"
	if [[ $shebang != '#!/bin/bash -p' ]]; then
		printf 'privileged-shell-test: %s does not use the privileged Bash shebang\n' "$relative" >&2
		exit 1
	fi
done

hardened_environment_helpers=(
	scripts/install-steward.sh
	scripts/install-node.sh
	scripts/configure-node.sh
	scripts/configure-admission.sh
	scripts/node-preflight.sh
	scripts/activate-node-release.sh
	scripts/uninstall-node.sh
	scripts/node-removal-guard.sh
	scripts/build-relay-image.sh
	scripts/preprovision-feasibility-handle.sh
)
for relative in "${hardened_environment_helpers[@]}"; do
	target="$root/$relative"
	grep -Eq '^PATH=/usr/sbin:/usr/bin:/sbin:/bin(:/usr/local/sbin:/usr/local/bin)?$' "$target" || {
		printf 'privileged-shell-test: %s does not replace caller PATH with a fixed search path\n' "$relative" >&2
		exit 1
	}
	grep -Fq 'LC_ALL=C' "$target"
	grep -Fq 'LANG=C' "$target"
	grep -Fq "IFS=\$' \\t\\n'" "$target"
	grep -Fq 'umask 077' "$target"
done
if grep -Eq '(^|[[:space:]])(source|\.)[[:space:]]+/etc/os-release' "$root/scripts/install-steward.sh"; then
	printf '%s\n' 'privileged-shell-test: installer evaluates shell-like host os-release input' >&2
	exit 1
fi
for helper in configure-node configure-admission activate-node-release; do
	grep -Fq 'readonly node_lock_directory=/run/steward-node' "$root/scripts/$helper.sh"
	grep -Fq "readonly node_lock_file=\$node_lock_directory/activation.lock" "$root/scripts/$helper.sh"
	if grep -Fq '/run/lock/steward-node-activation.lock' "$root/scripts/$helper.sh"; then
		printf 'privileged-shell-test: %s still uses the shared predictable legacy lock path\n' "$helper" >&2
		exit 1
	fi
done
grep -Fq -- '--node-lock-fd 9' "$root/scripts/configure-node.sh"
grep -Fq -- '--node-lock-fd)' "$root/scripts/configure-admission.sh"
grep -Fq "use_inherited_node_lock \"\$node_lock_fd\"" "$root/scripts/configure-admission.sh"

grep -Fq '#!/bin/bash -p' "$root/integrations/terraform/modules/steward-node/main.tf"
if grep -Eq "(^|[[:space:]])bash[[:space:]]+\"\\\$work/install-steward\\.sh\"" \
	"$root/integrations/terraform/modules/steward-node/main.tf"; then
	printf '%s\n' 'privileged-shell-test: Terraform bootstrap invokes the installer without -p' >&2
	exit 1
fi
grep -Fq "/bin/bash -p \"\$work/install-steward.sh\"" \
	"$root/integrations/terraform/modules/steward-node/main.tf"

# Debian and RPM invoke the packaged helper as an executable, so the kernel
# honors its reviewed shebang. A shell wrapper here would bypass that boundary.
for hook in "$root/packaging/debian/postinst" "$root/packaging/rpm/steward-node.spec.in"; do
	grep -Fq '/usr/lib/steward-node/release/scripts/install-node.sh --expected-version' "$hook"
	if grep -Eq '(bash|/bin/bash)[[:space:]].*install-node\.sh' "$hook"; then
		printf 'privileged-shell-test: package hook bypasses the install-node shebang: %s\n' "$hook" >&2
		exit 1
	fi
done

bash_env_marker="$work/bash-env-ran"
function_marker="$work/exported-function-ran"
hostile_env="$work/hostile-bash-env"
cat >"$hostile_env" <<'EOF'
: >"${STEWARD_BASH_ENV_MARKER:?}"
EOF

# Use a function the installers necessarily call on their validation error
# paths. The ordinary-Bash probes ensure the hostile fixtures are effective;
# the files are then removed before testing the supported invocations.
# shellcheck disable=SC2329 # Invoked by the child Bash process through export -f.
echo() {
	: >"${STEWARD_EXPORTED_FUNCTION_MARKER:?}"
	builtin echo "$@"
}
export -f echo
STEWARD_EXPORTED_FUNCTION_MARKER="$function_marker" /bin/bash -c 'echo probe' >/dev/null
[[ -f $function_marker ]]
STEWARD_BASH_ENV_MARKER="$bash_env_marker" BASH_ENV="$hostile_env" /bin/bash -c ':'
[[ -f $bash_env_marker ]]
rm -f -- "$function_marker" "$bash_env_marker"

run_supported_failure() {
	local target=$1 invocation=$2 label=$3 status
	set +e
	if [[ $invocation == explicit ]]; then
		STEWARD_BASH_ENV_MARKER="$bash_env_marker" \
			STEWARD_EXPORTED_FUNCTION_MARKER="$function_marker" \
			BASH_ENV="$hostile_env" /bin/bash -p "$target" --steward-invalid-option \
			>"$work/$label.out" 2>"$work/$label.err"
		status=$?
	else
		STEWARD_BASH_ENV_MARKER="$bash_env_marker" \
			STEWARD_EXPORTED_FUNCTION_MARKER="$function_marker" \
			BASH_ENV="$hostile_env" "$target" --steward-invalid-option \
			>"$work/$label.out" 2>"$work/$label.err"
		status=$?
	fi
	set -e
	if (( status != 2 )); then
		printf 'privileged-shell-test: supported %s invocation returned %d\n' "$label" "$status" >&2
		exit 1
	fi
	if [[ -e $bash_env_marker || -e $function_marker ]]; then
		printf 'privileged-shell-test: hostile shell payload ran during supported %s invocation\n' "$label" >&2
		exit 1
	fi
}

run_supported_failure "$root/scripts/install-steward.sh" explicit explicit
run_supported_failure "$root/scripts/install-steward.sh" direct direct
run_supported_failure "$root/scripts/install-node.sh" explicit explicit-package
run_supported_failure "$root/scripts/install-node.sh" direct direct-package
run_supported_failure "$root/scripts/configure-node.sh" explicit explicit-configure-node
run_supported_failure "$root/scripts/configure-node.sh" direct direct-configure-node
run_supported_failure "$root/scripts/configure-admission.sh" explicit explicit-configure-admission
run_supported_failure "$root/scripts/configure-admission.sh" direct direct-configure-admission
unset -f echo

grep -Fq $'\t/etc/steward/gateway.json' "$root/scripts/configure-node.sh"
grep -Fq '/usr/local/bin/stewardctl gateway identity set' "$root/scripts/configure-node.sh"

mkdir -p "$work/hostile-path"
cat >"$work/hostile-path/cat" <<EOF
#!/bin/sh
/usr/bin/touch '$work/hostile-path-ran'
exit 97
EOF
cat >"$work/hostile-path/readlink" <<EOF
#!/bin/sh
/usr/bin/touch '$work/hostile-path-ran'
exit 97
EOF
chmod 0755 "$work/hostile-path/cat"
chmod 0755 "$work/hostile-path/readlink"
for helper in configure-node configure-admission; do
	PATH="$work/hostile-path" /bin/bash -p "$root/scripts/$helper.sh" --help \
		>"$work/$helper-help.out" 2>"$work/$helper-help.err"
	if [[ -e $work/hostile-path-ran ]]; then
		printf 'privileged-shell-test: %s used a caller-controlled executable search path\n' "$helper" >&2
		exit 1
	fi
done

cat >"$work/untrusted-steward" <<EOF
#!/bin/sh
/usr/bin/touch '$work/untrusted-steward-ran'
exit 0
EOF
chmod 0755 "$work/untrusted-steward"
rm -f -- "$work/hostile-path-ran"
set +e
PATH="$work/hostile-path" STEWARD_BIN="$work/untrusted-steward" \
	/bin/bash -p "$root/scripts/node-preflight.sh" \
	>"$work/node-preflight-untrusted.out" 2>"$work/node-preflight-untrusted.err"
status=$?
set -e
if (( status != 2 )) || [[ -e $work/hostile-path-ran || -e $work/untrusted-steward-ran ]]; then
	printf '%s\n' 'privileged-shell-test: node-preflight accepted a caller-selected executable or PATH' >&2
	exit 1
fi

for helper in install-steward uninstall-node build-relay-image preprovision-feasibility-handle; do
	rm -f -- "$work/hostile-path-ran"
	set +e
	PATH="$work/hostile-path" /bin/bash -p "$root/scripts/$helper.sh" --help \
		>"$work/$helper-hostile-help.out" 2>"$work/$helper-hostile-help.err"
	status=$?
	set -e
	if (( status != 0 && status != 2 )); then
		printf 'privileged-shell-test: %s returned %d for its hostile-PATH help probe\n' "$helper" "$status" >&2
		exit 1
	fi
	if [[ -e $work/hostile-path-ran ]]; then
		printf 'privileged-shell-test: %s used a caller-controlled executable search path\n' "$helper" >&2
		exit 1
	fi
done

for installer in install-steward install-node; do
	set +e
	/bin/bash "$root/scripts/$installer.sh" --help >"$work/$installer.out" 2>"$work/$installer.err"
	status=$?
	set -e
	if (( status != 2 )) || ! grep -Fq '/bin/bash -p' "$work/$installer.err"; then
		printf 'privileged-shell-test: %s did not clearly reject ordinary Bash\n' "$installer" >&2
		exit 1
	fi
done

printf '%s\n' 'privileged-shell-test: root entrypoints ignore BASH_ENV and exported functions'
