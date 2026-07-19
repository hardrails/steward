#!/usr/bin/env bash
# Exercise offline install, idempotent upgrade, and rollback in a disposable Linux container.
set -Eeuo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${1:-} != --inside ]]; then
	command -v docker >/dev/null || { echo "control-install-smoke: docker is required" >&2; exit 2; }
	command -v go >/dev/null || { echo "control-install-smoke: go is required" >&2; exit 2; }
	case $(uname -m) in
		x86_64 | amd64) test_goarch=amd64 ;;
		aarch64 | arm64) test_goarch=arm64 ;;
		*) echo "control-install-smoke: unsupported test host architecture" >&2; exit 2 ;;
	esac
	real_fixture=$(mktemp -d "${TMPDIR:-/tmp}/steward-control-real.XXXXXX")
	trap 'rm -rf "$real_fixture"' EXIT
	(
		cd "$repo"
		CGO_ENABLED=0 GOOS=linux GOARCH="$test_goarch" go build -trimpath \
			-ldflags '-s -w -X github.com/hardrails/steward/internal/buildinfo.releaseVersion=v9.9.0' \
			-o "$real_fixture/steward-control" ./cmd/steward-control
	)
	cat >"$real_fixture/fake-control.go" <<'EOF'
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var version, failCheck, failInitialize, pauseInitialize string

const smokeToken = "steward_cp_v1_smoke_bootstrap"

func main() {
	initialize := flag.Bool("initialize", false, "")
	initializeWitness := flag.Bool("initialize-witness-key", false, "")
	initializeController := flag.Bool("initialize-controller-key", false, "")
	check := flag.Bool("check-config", false, "")
	showVersion := flag.Bool("version", false, "")
	state := flag.String("state-dir", "/var/lib/steward-control", "")
	auth := flag.String("auth-key-file", "/var/lib/steward-control/auth.key", "")
	admin := flag.String("admin-token-file", "", "")
	witnessPrivate := flag.String("witness-private-key-file", "/var/lib/steward-control/witness.private.pem", "")
	witnessPublic := flag.String("witness-public-key-file", "/var/lib/steward-control/witness.public.pem", "")
	controllerPrivate := flag.String("controller-private-key-file", "/var/lib/steward-control/controller.private.pem", "")
	controllerPublic := flag.String("controller-public-key-file", "/var/lib/steward-control/controller.public.pem", "")
	address := flag.String("addr", "127.0.0.1:8443", "")
	flag.String("tls-cert-file", "", "")
	flag.String("tls-key-file", "", "")
	flag.Bool("enable-metrics", false, "")
	flag.Duration("node-stale-after", 2*time.Minute, "")
	flag.Duration("evidence-stale-after", 5*time.Minute, "")
	flag.Duration("command-overdue-after", 5*time.Minute, "")
	flag.Duration("reconcile-interval", 5*time.Second, "")
	flag.String("controller-key-id", "controller-default", "")
	flag.Int("capacity-warning-percent", 80, "")
	flag.Parse()
	if *showVersion {
		fmt.Println("steward-control", version)
		return
	}
	if *initialize {
		must(os.MkdirAll(*state, 0o700))
		writeIfAbsent(filepath.Join(*state, "CURRENT"), []byte("manifest\n"))
		writeIfAbsent(*auth, make([]byte, 32))
		writeIfAbsent(filepath.Join(*state, "snapshot.1"), []byte("snapshot\n"))
		writeIfAbsent(*admin, []byte(smokeToken+"\n"))
		ensureWitness(*witnessPrivate, *witnessPublic)
		ensureController(*controllerPrivate, *controllerPublic)
		if pauseInitialize == "true" {
			time.Sleep(2 * time.Second)
		}
		if failInitialize == "true" {
			os.Exit(43)
		}
		return
	}
	if _, err := os.ReadFile(filepath.Join(*state, "CURRENT")); err != nil {
		must(err)
	}
	if _, err := os.ReadFile(*auth); err != nil {
		must(err)
	}
	if *initializeWitness {
		ensureWitness(*witnessPrivate, *witnessPublic)
		return
	}
	if *initializeController {
		ensureController(*controllerPrivate, *controllerPublic)
		return
	}
	ensureWitness(*witnessPrivate, *witnessPublic)
	ensureController(*controllerPrivate, *controllerPublic)
	lock, err := os.OpenFile(filepath.Join(*state, "LOCK"), os.O_RDWR|os.O_CREATE, 0o600)
	must(err)
	must(syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	if *check {
		must(syscall.Flock(int(lock.Fd()), syscall.LOCK_UN))
		must(lock.Close())
		if failCheck == "true" {
			os.Exit(42)
		}
		return
	}
	listener, err := net.Listen("tcp", *address)
	must(err)
	fmt.Fprintf(os.Stderr, "{\"msg\":\"Steward Control listening\",\"address\":%q}\n", listener.Addr().String())
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/tenants" ||
			request.URL.Query().Get("limit") != "1" || request.Header.Get("Authorization") != "Bearer "+smokeToken {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte("{\"tenants\":[]}\n"))
	})
	must(http.Serve(listener, handler))
}

func writeIfAbsent(path string, value []byte) {
	writeIfAbsentMode(path, value, 0o600)
}

func writeIfAbsentMode(path string, value []byte, mode os.FileMode) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if os.IsExist(err) {
		return
	}
	must(err)
	must(file.Chmod(mode))
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		must(err)
	}
	must(file.Close())
}

func ensureWitness(privatePath, publicPath string) {
	privateInfo, privateErr := os.Lstat(privatePath)
	publicInfo, publicErr := os.Lstat(publicPath)
	privateMissing := os.IsNotExist(privateErr)
	publicMissing := os.IsNotExist(publicErr)
	if privateErr != nil && !privateMissing {
		must(privateErr)
	}
	if publicErr != nil && !publicMissing {
		must(publicErr)
	}
	if privateMissing != publicMissing {
		must(fmt.Errorf("partial witness key pair"))
	}
	if privateMissing {
		writeIfAbsentMode(privatePath, []byte("smoke-witness-private\n"), 0o600)
		writeIfAbsentMode(publicPath, []byte("smoke-witness-public\n"), 0o644)
		privateInfo, privateErr = os.Lstat(privatePath)
		publicInfo, publicErr = os.Lstat(publicPath)
		must(privateErr)
		must(publicErr)
	}
	if !privateInfo.Mode().IsRegular() || privateInfo.Mode().Perm() != 0o600 ||
		!publicInfo.Mode().IsRegular() || publicInfo.Mode().Perm() != 0o644 {
		must(fmt.Errorf("unsafe witness key metadata"))
	}
	privateRaw, err := os.ReadFile(privatePath)
	must(err)
	publicRaw, err := os.ReadFile(publicPath)
	must(err)
	if string(privateRaw) != "smoke-witness-private\n" || string(publicRaw) != "smoke-witness-public\n" {
		must(fmt.Errorf("mismatched witness key pair"))
	}
}

func ensureController(privatePath, publicPath string) {
	privateInfo, privateErr := os.Lstat(privatePath)
	publicInfo, publicErr := os.Lstat(publicPath)
	privateMissing := os.IsNotExist(privateErr)
	publicMissing := os.IsNotExist(publicErr)
	if privateErr != nil && !privateMissing {
		must(privateErr)
	}
	if publicErr != nil && !publicMissing {
		must(publicErr)
	}
	if privateMissing != publicMissing {
		must(fmt.Errorf("partial controller key pair"))
	}
	if privateMissing {
		writeIfAbsentMode(privatePath, []byte("smoke-controller-private\n"), 0o600)
		writeIfAbsentMode(publicPath, []byte("smoke-controller-public\n"), 0o644)
		privateInfo, privateErr = os.Lstat(privatePath)
		publicInfo, publicErr = os.Lstat(publicPath)
		must(privateErr)
		must(publicErr)
	}
	if !privateInfo.Mode().IsRegular() || privateInfo.Mode().Perm() != 0o600 ||
		!publicInfo.Mode().IsRegular() || publicInfo.Mode().Perm() != 0o644 {
		must(fmt.Errorf("unsafe controller key metadata"))
	}
	privateRaw, err := os.ReadFile(privatePath)
	must(err)
	publicRaw, err := os.ReadFile(publicPath)
	must(err)
	if string(privateRaw) != "smoke-controller-private\n" || string(publicRaw) != "smoke-controller-public\n" {
		must(fmt.Errorf("mismatched controller key pair"))
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
EOF
	for specification in 'v0.8.0 false false true' 'v0.9.0 false true false' \
		'v1.0.0 false false false' 'v1.1.0 false false false' \
		'v1.2.0 true false false' 'v1.3.0 false false false'; do
		read -r fake_version fake_check fake_initialize fake_pause <<<"$specification"
		CGO_ENABLED=0 GOOS=linux GOARCH="$test_goarch" go build -trimpath \
			-ldflags "-s -w -X main.version=$fake_version -X main.failCheck=$fake_check -X main.failInitialize=$fake_initialize -X main.pauseInitialize=$fake_pause" \
			-o "$real_fixture/fake-$fake_version" "$real_fixture/fake-control.go"
	done
	docker run --rm --platform "linux/$test_goarch" -e TEST_GOARCH="$test_goarch" \
		-v "$repo:/repo:ro" -v "$real_fixture:/real:ro" ubuntu:24.04 \
		bash /repo/scripts/control-install-smoke.sh --inside
	exit
fi

export DEBIAN_FRONTEND=noninteractive
test_goarch=${TEST_GOARCH:-amd64}
apt-get update -qq
apt-get install --no-install-recommends -y -qq ca-certificates curl passwd util-linux >/dev/null

if /bin/bash /repo/scripts/install-control.sh --help >/tmp/control-unprivileged-shell.out 2>&1; then
	echo "control-install-smoke: installer accepted a non-privileged Bash invocation" >&2
	exit 1
fi
grep -Fq 'invoke this installer with /bin/bash -p' /tmp/control-unprivileged-shell.out
if /bin/bash /repo/scripts/control-doctor.sh --help >/tmp/control-doctor-unprivileged-shell.out 2>&1; then
	echo "control-install-smoke: control doctor accepted a non-privileged Bash invocation" >&2
	exit 1
fi
grep -Fq 'invoke this root-facing diagnostic with /bin/bash -p' \
	/tmp/control-doctor-unprivileged-shell.out

fixture=$(mktemp -d /root/steward-control-smoke.XXXXXX)
terraform_stage=$(mktemp -d /run/steward-control-bootstrap.XXXXXX)
trap 'rm -rf "$fixture" "$terraform_stage"' EXIT
trap 'status=$?; echo "control-install-smoke: unexpected failure at line $LINENO: $BASH_COMMAND" >&2; exit "$status"' ERR
[[ $(stat -c '%U:%G %a' "$terraform_stage") == 'root:root 700' ]]
mkdir -p "$fixture/assets" /run/fake-systemctl
admin_token_path=/root/steward-control-admin.token
admin_destination_id=$(printf '%s' "$admin_token_path" | sha256sum | awk '{print $1}')
publication_prefix="/root/.steward-control-admin-token.$admin_destination_id."
publication_pattern=".steward-control-admin-token.$admin_destination_id.*"
unrelated_sentinel=/root/.steward-control-admin-token.unrelated.backup
printf '%s\n' unrelated-token-sentinel >"$unrelated_sentinel"
chmod 0600 "$unrelated_sentinel"

cat >/usr/bin/systemd-analyze <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == verify ]]
grep -Fq 'User=steward-control' "${2:?}"
grep -Fq 'NoNewPrivileges=yes' "${2:?}"
grep -Fq 'CapabilityBoundingSet=' "${2:?}"
grep -Fq 'LimitNOFILE=4096' "${2:?}"
grep -Fq 'MemoryMax=1G' "${2:?}"
grep -Fq 'MemorySwapMax=0' "${2:?}"
EOF
chmod 0755 /usr/bin/systemd-analyze

cat >/usr/bin/systemctl <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=/run/fake-systemctl
kill_installer_behind_timeout() {
	local timeout_pid=$PPID installer_pid installer_command
	[[ $(cat "/proc/$timeout_pid/comm") == timeout ]] || exit 91
	installer_pid=$(awk '{print $4}' "/proc/$timeout_pid/stat")
	[[ $installer_pid =~ ^[1-9][0-9]*$ ]] || exit 91
	installer_command=$(tr '\0' ' ' <"/proc/$installer_pid/cmdline")
	[[ $installer_command == *'/repo/scripts/install-control.sh'* ]] || exit 91
	kill -KILL "$installer_pid"
}
printf '%s\n' "$*" >>"$state/calls"
case ${1:-} in
	is-active)
		if [[ -f $state/fail-activity-query ]]; then
			echo 'fake systemctl: activity query failed' >&2
			exit 2
		fi
		quiet=false
		for argument in "$@"; do [[ $argument != --quiet ]] || quiet=true; done
		if [[ ! -e /etc/systemd/system/steward-control.service && ! -L /etc/systemd/system/steward-control.service ]]; then
			[[ $quiet == true ]] || echo unknown
			exit 4
		fi
		if [[ -f $state/active ]]; then
			[[ $quiet == true ]] || echo active
			exit 0
		fi
		[[ $quiet == true ]] || echo inactive
		exit 3
		;;
	is-enabled)
		if [[ -f $state/fail-enablement-query ]]; then
			echo 'fake systemctl: enablement query failed' >&2
			exit 2
		fi
		if [[ ! -e /etc/systemd/system/steward-control.service && ! -L /etc/systemd/system/steward-control.service ]]; then
			echo not-found
			exit 1
		fi
		if [[ -f $state/enabled ]]; then echo enabled; exit 0; fi
		echo disabled
		exit 1
		;;
	stop)
		rm -f "$state/active"
		if [[ -f $state/kill-on-stop ]]; then
			rm -f "$state/kill-on-stop"
			kill_installer_behind_timeout
			sleep 0.1
		fi
		;;
	start | restart)
		touch "$state/active"
		if [[ -f $state/fail-next-restart ]]; then rm -f "$state/fail-next-restart"; exit 1; fi
		;;
	enable) touch "$state/enabled" ;;
	disable) rm -f "$state/enabled" ;;
	daemon-reload)
		if [[ -f $state/kill-on-daemon-reload ]]; then
			rm -f "$state/kill-on-daemon-reload"
			kill_installer_behind_timeout
			sleep 0.1
		fi
		;;
	show)
		case " $* " in
			*" -p User "*) echo steward-control ;;
			*" -p Group "*) echo steward-control ;;
			*" -p NoNewPrivileges "*) echo yes ;;
			*" -p SupplementaryGroups "*) echo ;;
			*) exit 1 ;;
		esac
		;;
	*) echo "fake systemctl: unsupported $*" >&2; exit 2 ;;
esac
EOF
chmod 0755 /usr/bin/systemctl

make_archive() {
	local version=$1 stage
	stage="$fixture/$version"
	mkdir -p "$stage"
	cp "/real/fake-$version" "$stage/steward-control"
	cp /repo/deploy/config/control.env "$stage/control.env"
	cp /repo/deploy/systemd/steward-control.service "$stage/steward-control.service"
	cp /repo/scripts/control-doctor.sh "$stage/control-doctor.sh"
	cp /repo/LICENSE "$stage/LICENSE"
	tar -C "$stage" -czf "$fixture/assets/steward-control_${version}_linux_${test_goarch}.tar.gz" \
		LICENSE control.env control-doctor.sh steward-control steward-control.service
}

make_archive v0.8.0
make_archive v0.9.0
make_archive v1.0.0
make_archive v1.1.0
make_archive v1.2.0
make_archive v1.3.0
(cd "$fixture/assets" && sha256sum ./*.tar.gz >checksums.txt)

install_version() {
	local version=$1
	shift
	/bin/bash -p /repo/scripts/install-control.sh --non-interactive \
		--artifact "$fixture/assets/steward-control_${version}_linux_${test_goarch}.tar.gz" \
		--checksums "$fixture/assets/checksums.txt" --version "$version" \
		--admin-token-out /root/steward-control-admin.token "$@"
}

install_version_from_terraform_stage() {
	local version=$1 archive="steward-control_${1}_linux_${test_goarch}.tar.gz"
	install -m 0600 -o root -g root "$fixture/assets/$archive" "$terraform_stage/$archive"
	install -m 0600 -o root -g root "$fixture/assets/checksums.txt" "$terraform_stage/checksums.txt"
	[[ $(stat -c '%U:%G %a:%h' "$terraform_stage/$archive") == 'root:root 600:1' ]]
	[[ $(stat -c '%U:%G %a:%h' "$terraform_stage/checksums.txt") == 'root:root 600:1' ]]
	/bin/bash -p /repo/scripts/install-control.sh --non-interactive \
		--artifact "$terraform_stage/$archive" --checksums "$terraform_stage/checksums.txt" \
		--version "$version" --admin-token-out /root/steward-control-admin.token
}

[[ ! -e /run/steward-host-role && ! -e /run/steward-control-installer && ! -e /var/lib/steward-control-installer ]]
/bin/bash -p /repo/scripts/install-control.sh --non-interactive --dry-run \
	--artifact "$fixture/assets/steward-control_v1.0.0_linux_${test_goarch}.tar.gz" \
	--checksums "$fixture/assets/checksums.txt" --version v1.0.0 \
	--admin-token-out /root/steward-control-admin.token >/tmp/control-clean-dry-run.out
grep -Fxq '  recovery:     none' /tmp/control-clean-dry-run.out
grep -Fxq '  metrics:      disabled' /tmp/control-clean-dry-run.out
grep -Fxq '  attention:    node=2m evidence=5m command=5m capacity=80%' /tmp/control-clean-dry-run.out
[[ ! -e /run/steward-host-role && ! -e /run/steward-control-installer && ! -e /var/lib/steward-control-installer ]]

install -d -m 0700 -o root -g root /run/steward-host-role
printf '%s\n' host-role-lock-sentinel >"$fixture/host-role-lock-victim"
chmod 0600 "$fixture/host-role-lock-victim"
ln -s "$fixture/host-role-lock-victim" /run/steward-host-role/role.lock
if install_version v1.0.0 >/tmp/control-symlink-host-role-lock.out 2>&1; then
	echo "control-install-smoke: installer followed a preseeded shared host-role lock symlink" >&2
	exit 1
fi
grep -Fq 'shared host-role lock has unsafe metadata' /tmp/control-symlink-host-role-lock.out
grep -Fxq host-role-lock-sentinel "$fixture/host-role-lock-victim"
rm -rf /run/steward-host-role

install -d -m 0700 -o root -g root /run/steward-control-installer
printf '%s\n' installer-lock-sentinel >"$fixture/installer-lock-victim"
chmod 0600 "$fixture/installer-lock-victim"
ln -s "$fixture/installer-lock-victim" /run/steward-control-installer/install.lock
if install_version v1.0.0 >/tmp/control-symlink-lock.out 2>&1; then
	echo "control-install-smoke: installer followed a preseeded private lock symlink" >&2
	exit 1
fi
grep -Fq 'private installer lock has unsafe metadata' /tmp/control-symlink-lock.out
grep -Fxq installer-lock-sentinel "$fixture/installer-lock-victim"
rm -rf /run/steward-control-installer

install -d -m 0777 -o root -g root /etc/steward-control
if install_version v1.0.0 >/tmp/control-unsafe-config-dir.out 2>&1; then
	echo "control-install-smoke: installer adopted an attacker-writable configuration directory" >&2
	exit 1
fi
grep -Fq 'every ancestor must be real, root-owned, and not group/other writable' \
	/tmp/control-unsafe-config-dir.out
[[ ! -e /run/fake-systemctl/calls && ! -e /var/lib/steward-control ]]
rm -rf /etc/steward-control

install -d -m 0755 -o root -g root /usr/local/libexec
install -d -m 0711 -o root -g root "$fixture/managed-directory-victim"
ln -s "$fixture/managed-directory-victim" /usr/local/libexec/steward-control
victim_metadata=$(stat -c '%u:%g:%a' "$fixture/managed-directory-victim")
if install_version v1.0.0 >/tmp/control-managed-directory-symlink.out 2>&1; then
	echo "control-install-smoke: installer followed a preseeded managed-directory symlink" >&2
	exit 1
fi
grep -Fq 'managed directory or its parent chain is unsafe: /usr/local/libexec/steward-control' \
	/tmp/control-managed-directory-symlink.out
[[ $(stat -c '%u:%g:%a' "$fixture/managed-directory-victim") == "$victim_metadata" ]]
if getent passwd steward-control >/dev/null; then
	echo "control-install-smoke: managed-directory preflight failure created a service identity" >&2
	exit 1
fi
rm /usr/local/libexec/steward-control

# The controller is deliberately a separate host role. A node installation
# marker must stop the installer before it creates an identity, state, or a
# service transaction.
install -d -m 0755 -o root -g root /opt/steward/releases
if install_version v1.0.0 >/tmp/control-node-colocation.out 2>&1; then
	echo "control-install-smoke: controller installer accepted a node co-location marker" >&2
	exit 1
fi
grep -Fq 'controller and Executor node installations must use separate hosts; found node marker /opt/steward/releases' \
	/tmp/control-node-colocation.out
[[ ! -e /run/fake-systemctl/calls && ! -e /var/lib/steward-control ]]
if getent passwd steward-control >/dev/null; then
	echo "control-install-smoke: co-location refusal created the controller service identity" >&2
	exit 1
fi
rm -rf /opt/steward

(
	for _ in {1..200}; do
		if compgen -G '/run/steward-control-handoff.*/admin.token' >/dev/null; then
			printf '%s\n' steward_cp_v1_racing_destination >/root/steward-control-admin.token
			chmod 0600 /root/steward-control-admin.token
			exit 0
		fi
		sleep 0.01
	done
	exit 1
) &
publication_racer=$!
if install_version v0.8.0 >/tmp/control-publication-race.out 2>&1; then
	echo "control-install-smoke: raced admin token destination was overwritten" >&2
	exit 1
fi
if ! wait "$publication_racer"; then
	echo "control-install-smoke: installer failed before token publication race was exercised" >&2
	cat /tmp/control-publication-race.out >&2
	exit 1
fi
grep -Fxq steward_cp_v1_racing_destination /root/steward-control-admin.token
[[ ! -e /var/lib/steward-control ]]
if find /root -maxdepth 1 -name "$publication_pattern" -print -quit | grep -q .; then
	echo "control-install-smoke: failed token publication left its temporary file" >&2
	exit 1
fi
grep -Fxq unrelated-token-sentinel "$unrelated_sentinel"
rm /root/steward-control-admin.token

if install_version v0.9.0 >/tmp/control-initialize-failure.out 2>&1; then
	echo "control-install-smoke: failed initialization unexpectedly succeeded" >&2
	exit 1
fi
if [[ -e /var/lib/steward-control-installer/transaction ]]; then
	echo "control-install-smoke: handled initialization failure left a durable transaction" >&2
	sed -n '1,160p' /tmp/control-initialize-failure.out >&2
	find /var/lib/steward-control-installer/transaction -maxdepth 2 \
		-printf '%p %y %u:%g %m %s\n' >&2 || true
	exit 1
fi
[[ ! -e /var/lib/steward-control && ! -e /root/steward-control-admin.token ]]
[[ ! -e /opt/steward-control/current && ! -e /etc/steward-control/control.env ]]

install -d -m 0700 -o root -g root /var/lib/steward-control
if install_version v0.9.0 >/tmp/control-preexisting-state-failure.out 2>&1; then
	echo "control-install-smoke: failed initialization in a caller-owned state path unexpectedly succeeded" >&2
	exit 1
fi
if [[ ! -d /var/lib/steward-control || -e /var/lib/steward-control/CURRENT ]]; then
	echo "control-install-smoke: rollback did not restore caller-owned empty state" >&2
	sed -n '1,120p' /tmp/control-preexisting-state-failure.out >&2
	find /var/lib/steward-control /var/lib/steward-control-installer -maxdepth 3 -printf '%p %y %u:%g %m\n' 2>/dev/null >&2 || true
	exit 1
fi
[[ -z $(find /var/lib/steward-control -mindepth 1 -maxdepth 1 -print -quit) ]]
[[ ! -e /root/steward-control-admin.token ]]
rm -rf /var/lib/steward-control

# First interrupt token publication immediately after mktemp reserved an empty,
# one-link candidate. The installer process is killed externally while the
# wrapper is paused, so no EXIT trap can clean the candidate or durable journal.
mv /usr/bin/mktemp /usr/bin/mktemp.control-smoke-real
cat >/usr/bin/mktemp <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
result=$(/usr/bin/mktemp.control-smoke-real "$@")
if [[ $result == /root/.steward-control-admin-token.* ]]; then
	printf '%s\n' "$result" >/run/fake-systemctl/token-reservation-path
	printf '%s\n' "$BASHPID" >/run/fake-systemctl/token-reservation-wrapper-pid
	printf '%s\n' reserved >/run/fake-systemctl/token-reserved
	while :; do :; done
fi
printf '%s\n' "$result"
EOF
chmod 0755 /usr/bin/mktemp
/bin/bash -p /repo/scripts/install-control.sh --non-interactive \
	--artifact "$fixture/assets/steward-control_v1.0.0_linux_${test_goarch}.tar.gz" \
	--checksums "$fixture/assets/checksums.txt" --version v1.0.0 \
	--admin-token-out /root/steward-control-admin.token \
	>/tmp/control-token-reservation-crash.out 2>&1 &
reservation_installer_pid=$!
reservation_reached=false
for _ in {1..500}; do
	if [[ -s /run/fake-systemctl/token-reserved ]]; then reservation_reached=true; break; fi
	sleep 0.01
done
if [[ $reservation_reached != true ]]; then
	echo "control-install-smoke: first install did not reach the empty token reservation window" >&2
	kill -KILL "$reservation_installer_pid" 2>/dev/null || true
	exit 1
fi
reservation_candidate=$(</run/fake-systemctl/token-reservation-path)
reservation_wrapper_pid=$(</run/fake-systemctl/token-reservation-wrapper-pid)
[[ -f $reservation_candidate && ! -L $reservation_candidate ]]
[[ $(stat -c '%U:%G %a:%h:%s' "$reservation_candidate") == 'root:root 600:1:0' ]]
kill -KILL "$reservation_installer_pid" "$reservation_wrapper_pid" 2>/dev/null || true
reservation_crash_status=0
if wait "$reservation_installer_pid"; then
	reservation_crash_status=0
else
	reservation_crash_status=$?
fi
rm -f /usr/bin/mktemp
mv /usr/bin/mktemp.control-smoke-real /usr/bin/mktemp
if (( reservation_crash_status < 128 )); then
	echo "control-install-smoke: empty token reservation SIGKILL fixture did not terminate the first install" >&2
	exit 1
fi
if ! grep -Fxq prepared /var/lib/steward-control-installer/transaction/phase; then
	echo "control-install-smoke: empty reservation crash did not preserve a prepared transaction" >&2
	find /var/lib/steward-control-installer -maxdepth 3 -printf '%p %y %u:%g %m %s\n' >&2 || true
	exit 1
fi
if [[ -e /root/steward-control-admin.token ]]; then
	echo "control-install-smoke: empty reservation crash published the token destination" >&2
	exit 1
fi
if [[ -e /run/fake-systemctl/active || -e /run/fake-systemctl/enabled ]]; then
	echo "control-install-smoke: empty reservation crash unexpectedly activated the service" >&2
	exit 1
fi

# The next invocation must first recover that empty reservation, then is
# interrupted in the second narrow window: after link(2) publishes the token,
# but before the temporary hardlink is removed.
mv /usr/bin/ln /usr/bin/ln.control-smoke-real
cat >/usr/bin/ln <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
/usr/bin/ln.control-smoke-real "$@"
destination=${!#}
if [[ -e /run/fake-systemctl/kill-on-token-hardlink &&
	$destination == /root/steward-control-admin.token ]]; then
	printf '%s\n' hardlink-created >/run/fake-systemctl/token-hardlink-created
	rm -f /run/fake-systemctl/kill-on-token-hardlink
	kill -KILL "$PPID"
fi
EOF
chmod 0755 /usr/bin/ln
touch /run/fake-systemctl/kill-on-token-hardlink
if install_version v1.0.0 >/tmp/control-token-hardlink-crash.out 2>&1; then
	token_crash_status=0
else
	token_crash_status=$?
fi
rm -f /usr/bin/ln
mv /usr/bin/ln.control-smoke-real /usr/bin/ln
if (( token_crash_status < 128 )); then
	echo "control-install-smoke: token hardlink SIGKILL fixture did not terminate the first install" >&2
	sed -n '1,160p' /tmp/control-token-hardlink-crash.out >&2
	exit 1
fi
grep -Fq 'recovered the previous controller state from an interrupted durable transaction' \
	/tmp/control-token-hardlink-crash.out
grep -Fxq hardlink-created /run/fake-systemctl/token-hardlink-created
grep -Fxq prepared /var/lib/steward-control-installer/transaction/phase
[[ -f /root/steward-control-admin.token ]]
[[ $(stat -c '%h' /root/steward-control-admin.token) == 2 ]]
[[ $(find /root -maxdepth 1 -name "$publication_pattern" -type f -printf . | wc -c) == 1 ]]
hardlink_candidate=$(find /root -maxdepth 1 -name "$publication_pattern" -type f -print)
[[ $(stat -c '%h:%s' "$hardlink_candidate") == "2:$(stat -c '%s' /root/steward-control-admin.token)" ]]
[[ $(stat -c '%d:%i' "$hardlink_candidate") == "$(stat -c '%d:%i' /root/steward-control-admin.token)" ]]
[[ ! -e /opt/steward-control/current && ! -e /usr/local/bin/steward-control ]]
[[ ! -e /run/fake-systemctl/active && ! -e /run/fake-systemctl/enabled ]]

install_version_from_terraform_stage v1.0.0 >/tmp/control-token-hardlink-recovery.out 2>&1
grep -Fq 'recovered the previous controller state from an interrupted durable transaction' \
	/tmp/control-token-hardlink-recovery.out
[[ ! -e /var/lib/steward-control-installer/transaction ]]
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.0.0 ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control) == 'steward-control:steward-control 700' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/witness.private.pem) == 'steward-control:steward-control 600' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/witness.public.pem) == 'steward-control:steward-control 644' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/controller.private.pem) == 'steward-control:steward-control 600' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/controller.public.pem) == 'steward-control:steward-control 644' ]]
[[ $(stat -c '%U:%G %a' /root/steward-control-admin.token) == 'root:root 600' ]]
[[ $(stat -c '%h' /root/steward-control-admin.token) == 1 ]]
[[ $(id -nG steward-control) == steward-control ]]
[[ -f /run/fake-systemctl/active && -f /run/fake-systemctl/enabled ]]
grep -Fxq 'STEWARD_CONTROL_ADDR=127.0.0.1:8443' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE=/var/lib/steward-control/witness.private.pem' \
	/etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE=/var/lib/steward-control/witness.public.pem' \
	/etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE=/var/lib/steward-control/controller.private.pem' \
	/etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE=/var/lib/steward-control/controller.public.pem' \
	/etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_CONTROLLER_KEY_ID=controller-default' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_RECONCILE_INTERVAL=5s' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_ENABLE_METRICS=false' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_NODE_STALE_AFTER=2m' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_EVIDENCE_STALE_AFTER=5m' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_COMMAND_OVERDUE_AFTER=5m' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_CAPACITY_WARNING_PERCENT=80' /etc/steward-control/control.env
if find /root -maxdepth 1 -name "$publication_pattern" -print -quit | grep -q .; then
	echo "control-install-smoke: crash recovery left a temporary admin-token hardlink" >&2
	exit 1
fi

install_version v1.0.0 --enable-metrics --node-stale-after 3m \
	--evidence-stale-after 7m --command-overdue-after 11m \
	--capacity-warning-percent 75
grep -Fxq 'STEWARD_CONTROL_ENABLE_METRICS=true' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_NODE_STALE_AFTER=3m' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_EVIDENCE_STALE_AFTER=7m' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_COMMAND_OVERDUE_AFTER=11m' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_CAPACITY_WARNING_PERCENT=75' /etc/steward-control/control.env
install_version v1.0.0
grep -Fxq 'STEWARD_CONTROL_ENABLE_METRICS=true' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_NODE_STALE_AFTER=3m' /etc/steward-control/control.env
install_version v1.0.0 --disable-metrics --node-stale-after 2m \
	--evidence-stale-after 5m --command-overdue-after 5m \
	--capacity-warning-percent 80
grep -Fxq 'STEWARD_CONTROL_ENABLE_METRICS=false' /etc/steward-control/control.env

assert_identity_collision_rejected() {
	local label=$1 output=$2 doctor_failure=$3
	if install_version v1.0.0 >"/tmp/control-$label-installer.out" 2>&1; then
		echo "control-install-smoke: installer accepted $label" >&2
		exit 1
	fi
	grep -Fq 'unique nonzero numeric UID/GID authority' "/tmp/control-$label-installer.out"
	/bin/bash -p /repo/scripts/control-doctor.sh >"$output" 2>&1 || true
	if ! grep -Fq "FAIL $doctor_failure" "$output"; then
		echo "control-install-smoke: doctor did not diagnose $label" >&2
		sed -n '1,80p' "$output" >&2
		exit 1
	fi
}

service_uid=$(id -u steward-control)
service_gid=$(id -g steward-control)
if getent group docker >/dev/null; then
	echo "control-install-smoke: disposable fixture unexpectedly already has a Docker group" >&2
	exit 1
fi
groupadd --non-unique --gid "$service_gid" docker
assert_identity_collision_rejected duplicate-docker-gid /tmp/control-duplicate-docker-gid-doctor.out \
	'steward-control numeric group authority collides with Docker'
sed -i '/^docker:/d' /etc/group /etc/gshadow
useradd --system --non-unique --uid "$service_uid" --gid "$service_gid" \
	--home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin steward-control-duplicate
assert_identity_collision_rejected duplicate-service-uid /tmp/control-duplicate-service-uid-doctor.out \
	'steward-control service identity is missing, privileged, login-capable, or not isolated'
userdel steward-control-duplicate

cp -p /etc/steward-control/control.env "$fixture/doctor-loopback.env"
printf '%s\n' certificate >/etc/steward-control/tls.crt
printf '%s\n' private-key >/etc/steward-control/tls.key
chown root:steward-control /etc/steward-control/tls.crt
chown steward-control:steward-control /etc/steward-control/tls.key
chmod 0640 /etc/steward-control/tls.crt
chmod 0600 /etc/steward-control/tls.key
cat >/etc/steward-control/control.env <<'EOF'
STEWARD_CONTROL_ADDR=0.0.0.0:8443
STEWARD_CONTROL_STATE_DIR=/var/lib/steward-control
STEWARD_CONTROL_AUTH_KEY_FILE=/var/lib/steward-control/auth.key
STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE=/var/lib/steward-control/witness.private.pem
STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE=/var/lib/steward-control/witness.public.pem
STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE=/var/lib/steward-control/controller.private.pem
STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE=/var/lib/steward-control/controller.public.pem
STEWARD_CONTROL_CONTROLLER_KEY_ID=controller-default
STEWARD_CONTROL_RECONCILE_INTERVAL=5s
STEWARD_CONTROL_TLS_CERT_FILE=/etc/steward-control/tls.crt
STEWARD_CONTROL_TLS_KEY_FILE=/etc/steward-control/tls.key
STEWARD_CONTROL_ENABLE_METRICS=false
STEWARD_CONTROL_NODE_STALE_AFTER=2m
STEWARD_CONTROL_EVIDENCE_STALE_AFTER=5m
STEWARD_CONTROL_COMMAND_OVERDUE_AFTER=5m
STEWARD_CONTROL_CAPACITY_WARNING_PERCENT=80
EOF
chown root:root /etc/steward-control/control.env
chmod 0600 /etc/steward-control/control.env
grep -Fq 'timeout 5 /bin/bash -p -c' /repo/scripts/control-doctor.sh
printf '%s\n' 'touch /tmp/steward-control-doctor-bash-env-executed' >"$fixture/doctor-bash-env"
rm -f /tmp/steward-control-doctor-bash-env-executed /tmp/steward-control-doctor-function-executed \
	/tmp/steward-control-doctor-exec-function-executed
if (
	# shellcheck disable=SC2329 # Exported fixture must remain uncalled under Bash privileged mode.
	systemctl() { touch /tmp/steward-control-doctor-function-executed; /usr/bin/systemctl "$@"; }
	# shellcheck disable=SC2329 # The wildcard-listener child must not import this exported builtin override.
	exec() { touch /tmp/steward-control-doctor-exec-function-executed; builtin exec "$@"; }
	export -f systemctl exec
	BASH_ENV="$fixture/doctor-bash-env" /bin/bash -p /repo/scripts/control-doctor.sh --json \
		>/tmp/control-doctor-hostile-env.out 2>&1
); then
	:
else
	:
fi
[[ ! -e /tmp/steward-control-doctor-bash-env-executed ]]
[[ ! -e /tmp/steward-control-doctor-function-executed ]]
[[ ! -e /tmp/steward-control-doctor-exec-function-executed ]]
install -m 0600 -o root -g root "$fixture/doctor-loopback.env" /etc/steward-control/control.env
rm -f /etc/steward-control/tls.crt /etc/steward-control/tls.key

original_service_shell=$(getent passwd steward-control | cut -d: -f7)
usermod --shell /bin/bash steward-control
if install_version v1.0.0 >/tmp/control-login-shell.out 2>&1; then
	echo "control-install-smoke: installer adopted a login-capable service identity" >&2
	exit 1
fi
if /bin/bash -p /repo/scripts/control-doctor.sh >/tmp/control-login-shell-doctor.out 2>&1; then
	echo "control-install-smoke: doctor accepted a login-capable service identity" >&2
	exit 1
fi
grep -Fq 'FAIL steward-control service identity is missing, privileged, login-capable, or not isolated' \
	/tmp/control-login-shell-doctor.out
usermod --shell "$original_service_shell" steward-control
printf '%s:%s\n' steward-control 'temporary-Smoke-password-1' | chpasswd
if install_version v1.0.0 >/tmp/control-unlocked-password.out 2>&1; then
	echo "control-install-smoke: installer adopted an unlocked service identity" >&2
	exit 1
fi
if /bin/bash -p /repo/scripts/control-doctor.sh >/tmp/control-unlocked-password-doctor.out 2>&1; then
	echo "control-install-smoke: doctor accepted an unlocked service identity" >&2
	exit 1
fi
grep -Fq 'FAIL steward-control service identity is missing, privileged, login-capable, or not isolated' \
	/tmp/control-unlocked-password-doctor.out
passwd -l steward-control >/dev/null

witness_private=/var/lib/steward-control/witness.private.pem
witness_public=/var/lib/steward-control/witness.public.pem
controller_private=/var/lib/steward-control/controller.private.pem
controller_public=/var/lib/steward-control/controller.public.pem
cp -p "$witness_private" "$fixture/witness.private.pem"
cp -p "$witness_public" "$fixture/witness.public.pem"
cp -p "$controller_private" "$fixture/controller.private.pem"
cp -p "$controller_public" "$fixture/controller.public.pem"
assert_witness_state_rejected() {
	local label=$1
	if install_version v1.0.0 >"/tmp/control-witness-$label.out" 2>&1; then
		echo "control-install-smoke: installer accepted $label witness-key state" >&2
		exit 1
	fi
	[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.0.0 ]]
	[[ ! -e /var/lib/steward-control-installer/transaction ]]
}

chmod 0640 "$witness_private"
assert_witness_state_rejected unsafe-permissions
chmod 0600 "$witness_private"

rm -f "$witness_public"
assert_witness_state_rejected partial-pair
[[ ! -e $witness_public ]]
install -m 0644 -o steward-control -g steward-control "$fixture/witness.public.pem" "$witness_public"

rm -f "$witness_public"
ln -s "$fixture/witness.public.pem" "$witness_public"
assert_witness_state_rejected public-symlink
rm -f "$witness_public"
install -m 0644 -o steward-control -g steward-control "$fixture/witness.public.pem" "$witness_public"

printf '%s\n' mismatched-public-key >"$witness_public"
chown steward-control:steward-control "$witness_public"
chmod 0644 "$witness_public"
assert_witness_state_rejected mismatched-pair
install -m 0644 -o steward-control -g steward-control "$fixture/witness.public.pem" "$witness_public"

assert_controller_state_rejected() {
	local label=$1
	if install_version v1.0.0 >"/tmp/control-controller-$label.out" 2>&1; then
		echo "control-install-smoke: installer accepted $label controller signing-key state" >&2
		exit 1
	fi
	[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.0.0 ]]
	[[ ! -e /var/lib/steward-control-installer/transaction ]]
}

chmod 0640 "$controller_private"
assert_controller_state_rejected unsafe-permissions
chmod 0600 "$controller_private"

rm -f "$controller_public"
assert_controller_state_rejected partial-pair
[[ ! -e $controller_public ]]
install -m 0644 -o steward-control -g steward-control "$fixture/controller.public.pem" "$controller_public"

rm -f "$controller_public"
ln -s "$fixture/controller.public.pem" "$controller_public"
assert_controller_state_rejected public-symlink
rm -f "$controller_public"
install -m 0644 -o steward-control -g steward-control "$fixture/controller.public.pem" "$controller_public"

printf '%s\n' mismatched-public-key >"$controller_public"
chown steward-control:steward-control "$controller_public"
chmod 0644 "$controller_public"
assert_controller_state_rejected mismatched-pair
install -m 0644 -o steward-control -g steward-control "$fixture/controller.public.pem" "$controller_public"

# Simulate an upgrade from durable state and control.env created before witness
# keys existed. The candidate must create the pair once, publish the stable
# paths, and preserve the bytes on every later rerun and upgrade.
rm -f "$witness_private" "$witness_public"
sed -i '/^STEWARD_CONTROL_WITNESS_.*_KEY_FILE=/d' /etc/steward-control/control.env
install_version v1.0.0
[[ $(stat -c '%U:%G %a' "$witness_private") == 'steward-control:steward-control 600' ]]
[[ $(stat -c '%U:%G %a' "$witness_public") == 'steward-control:steward-control 644' ]]
legacy_witness_hash=$(sha256sum "$witness_private" "$witness_public")
grep -Fxq "STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE=$witness_private" /etc/steward-control/control.env
grep -Fxq "STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE=$witness_public" /etc/steward-control/control.env

state_hash=$(sha256sum /var/lib/steward-control/CURRENT /var/lib/steward-control/auth.key \
	/var/lib/steward-control/snapshot.1 "$witness_private" "$witness_public")
token_hash=$(sha256sum /root/steward-control-admin.token)
install_version v1.0.0
[[ $(sha256sum /root/steward-control-admin.token) == "$token_hash" ]]
[[ $(sha256sum "$witness_private" "$witness_public") == "$legacy_witness_hash" ]]

# Simulate an upgrade from controller state created before online delegated
# reconciliation. The installer must add one purpose-separated signing pair and
# publish its stable identity without replacing it on later runs.
rm -f "$controller_private" "$controller_public"
sed -i '/^STEWARD_CONTROL_CONTROLLER_/d; /^STEWARD_CONTROL_RECONCILE_INTERVAL=/d' /etc/steward-control/control.env
install_version v1.0.0
[[ $(stat -c '%U:%G %a' "$controller_private") == 'steward-control:steward-control 600' ]]
[[ $(stat -c '%U:%G %a' "$controller_public") == 'steward-control:steward-control 644' ]]
legacy_controller_hash=$(sha256sum "$controller_private" "$controller_public")
grep -Fxq "STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE=$controller_private" /etc/steward-control/control.env
grep -Fxq "STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE=$controller_public" /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_CONTROLLER_KEY_ID=controller-default' /etc/steward-control/control.env
grep -Fxq 'STEWARD_CONTROL_RECONCILE_INTERVAL=5s' /etc/steward-control/control.env
install_version v1.0.0
[[ $(sha256sum "$controller_private" "$controller_public") == "$legacy_controller_hash" ]]

install_version v1.1.0
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
[[ $(sha256sum /var/lib/steward-control/CURRENT /var/lib/steward-control/auth.key \
	/var/lib/steward-control/snapshot.1 "$witness_private" "$witness_public") == "$state_hash" ]]
[[ $(sha256sum /root/steward-control-admin.token) == "$token_hash" ]]

for query in activity enablement; do
	touch "/run/fake-systemctl/fail-${query}-query"
	if install_version v1.1.0 >"/tmp/control-${query}-query-failure.out" 2>&1; then
		echo "control-install-smoke: ambiguous systemd $query query was accepted" >&2
		exit 1
	fi
	rm -f "/run/fake-systemctl/fail-${query}-query"
	grep -Fq "could not determine the exact ${query} state of steward-control.service" \
		"/tmp/control-${query}-query-failure.out"
	[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
	[[ -f /run/fake-systemctl/active && -f /run/fake-systemctl/enabled ]]
	[[ ! -e /var/lib/steward-control-installer/transaction ]]
done

assert_durable_crash_recovery() {
	local kill_marker=$1 label=$2 status config_hash pending_copy state_before
	local current_before binary_before doctor_before unit_before active_before enabled_before
	config_hash=$(sha256sum /etc/steward-control/control.env)
	touch "/run/fake-systemctl/$kill_marker"
	if /bin/bash -p /repo/scripts/install-control.sh --non-interactive \
		--artifact "$fixture/assets/steward-control_v1.3.0_linux_${test_goarch}.tar.gz" \
		--checksums "$fixture/assets/checksums.txt" --version v1.3.0 \
		--admin-token-out /root/steward-control-admin.token \
		>"/tmp/control-durable-$label.out" 2>&1; then
		status=0
	else
		status=$?
	fi
	if (( status == 0 )); then
		echo "control-install-smoke: SIGKILL fixture at $label did not interrupt the installer" >&2
		exit 1
	fi
	grep -Fxq prepared /var/lib/steward-control-installer/transaction/phase
	pending_copy="$fixture/pending-$label"
	rm -rf -- "$pending_copy"
	cp -a /var/lib/steward-control-installer/transaction "$pending_copy"
	current_before=$(readlink /opt/steward-control/current)
	binary_before=$(readlink /usr/local/bin/steward-control)
	doctor_before=$(readlink /usr/local/libexec/steward-control/control-doctor)
	unit_before=$(readlink /etc/systemd/system/steward-control.service)
	state_before=$(find /var/lib/steward-control -maxdepth 1 -type f -exec sha256sum {} + | sort)
	active_before=$([[ -e /run/fake-systemctl/active ]] && echo yes || echo no)
	enabled_before=$([[ -e /run/fake-systemctl/enabled ]] && echo yes || echo no)
	/bin/bash -p /repo/scripts/install-control.sh --non-interactive --dry-run \
		--artifact "$fixture/assets/steward-control_v1.1.0_linux_${test_goarch}.tar.gz" \
		--checksums "$fixture/assets/checksums.txt" --version v1.1.0 \
		--admin-token-out /root/steward-control-admin.token \
		>"/tmp/control-pending-$label-dry-run.out"
	grep -Fxq '  recovery:     pending-on-next-install' "/tmp/control-pending-$label-dry-run.out"
	diff -r --no-dereference "$pending_copy" /var/lib/steward-control-installer/transaction
	[[ $(readlink /opt/steward-control/current) == "$current_before" ]]
	[[ $(readlink /usr/local/bin/steward-control) == "$binary_before" ]]
	[[ $(readlink /usr/local/libexec/steward-control/control-doctor) == "$doctor_before" ]]
	[[ $(readlink /etc/systemd/system/steward-control.service) == "$unit_before" ]]
	[[ $(sha256sum /etc/steward-control/control.env) == "$config_hash" ]]
	[[ $(find /var/lib/steward-control -maxdepth 1 -type f -exec sha256sum {} + | sort) == "$state_before" ]]
	[[ $([[ -e /run/fake-systemctl/active ]] && echo yes || echo no) == "$active_before" ]]
	[[ $([[ -e /run/fake-systemctl/enabled ]] && echo yes || echo no) == "$enabled_before" ]]
	[[ $(sha256sum /root/steward-control-admin.token) == "$token_hash" ]]
	install_version v1.1.0 >/tmp/control-durable-recovery.out 2>&1
	grep -Fq 'recovered the previous controller state from an interrupted durable transaction' \
		/tmp/control-durable-recovery.out
	[[ ! -e /var/lib/steward-control-installer/transaction ]]
	[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
	[[ $(sha256sum /etc/steward-control/control.env) == "$config_hash" ]]
	[[ -f /run/fake-systemctl/active && -f /run/fake-systemctl/enabled ]]
	[[ $(sha256sum /root/steward-control-admin.token) == "$token_hash" ]]
}
assert_durable_crash_recovery kill-on-stop service-stop
assert_durable_crash_recovery kill-on-daemon-reload post-link-config

reject_hostile_existing_config() {
	local label=$1 status
	if timeout 5 /bin/bash -p /repo/scripts/install-control.sh --non-interactive \
		--artifact "$fixture/assets/steward-control_v1.1.0_linux_${test_goarch}.tar.gz" \
		--checksums "$fixture/assets/checksums.txt" --version v1.1.0 \
		--admin-token-out /root/steward-control-admin.token \
		>/tmp/control-hostile-config.out 2>&1; then
		status=0
	else
		status=$?
	fi
	if (( status == 0 || status == 124 )); then
		echo "control-install-smoke: hostile $label configuration succeeded or escaped its time bound" >&2
		exit 1
	fi
}
cp -p /etc/steward-control/control.env "$fixture/control.env.safe"
calls_before_config=$(wc -l </run/fake-systemctl/calls)
rm /etc/steward-control/control.env
mkfifo -m 0600 /etc/steward-control/control.env
reject_hostile_existing_config fifo
rm /etc/steward-control/control.env
ln -s "$fixture/control.env.safe" /etc/steward-control/control.env
reject_hostile_existing_config symlink
rm /etc/steward-control/control.env
install -m 0600 -o root -g root "$fixture/control.env.safe" /etc/steward-control/control.env
truncate -s 16385 /etc/steward-control/control.env
reject_hostile_existing_config oversized
install -m 0600 -o root -g root "$fixture/control.env.safe" /etc/steward-control/control.env
truncate -s 16384 /etc/steward-control/control.env
touch "$fixture/grow-config"
(
	while [[ -e $fixture/grow-config ]]; do
		truncate -s 16385 /etc/steward-control/control.env
		truncate -s 16384 /etc/steward-control/control.env
	done
) &
config_growth_pid=$!
reject_hostile_existing_config growth
rm -f "$fixture/grow-config"
wait "$config_growth_pid"
install -m 0600 -o root -g root "$fixture/control.env.safe" /etc/steward-control/control.env
[[ $(wc -l </run/fake-systemctl/calls) -eq $calls_before_config ]]
[[ -f /run/fake-systemctl/active ]]

reject_hostile_doctor_config() {
	local label=$1 status
	if timeout 5 /bin/bash -p /repo/scripts/control-doctor.sh \
		>"/tmp/control-doctor-hostile-config-$label.out" 2>&1; then
		status=0
	else
		status=$?
	fi
	if (( status == 0 || status == 124 )); then
		echo "control-install-smoke: doctor accepted or hung on $label control.env" >&2
		exit 1
	fi
	if grep -Fq 'ok   control.env contains only supported settings' \
		"/tmp/control-doctor-hostile-config-$label.out"; then
		echo "control-install-smoke: doctor parsed hostile $label control.env as trusted" >&2
		exit 1
	fi
}
rm /etc/steward-control/control.env
mkfifo -m 0600 /etc/steward-control/control.env
reject_hostile_doctor_config fifo
rm /etc/steward-control/control.env
install -m 0600 -o root -g root "$fixture/control.env.safe" /etc/steward-control/control.env
ln /etc/steward-control/control.env "$fixture/control.env.hardlink-twin"
reject_hostile_doctor_config hardlink
rm "$fixture/control.env.hardlink-twin"
install -m 0600 -o root -g root "$fixture/control.env.safe" /etc/steward-control/control.env

reject_hostile_local_source() {
	local label=$1 artifact_path=$2 checksums_path=$3 status
	if timeout 10 /bin/bash -p /repo/scripts/install-control.sh --non-interactive \
		--artifact "$artifact_path" --checksums "$checksums_path" --version v1.1.0 \
		>/tmp/control-hostile-source.out 2>&1; then
		status=0
	else
		status=$?
	fi
	if (( status == 0 || status == 124 )); then
		echo "control-install-smoke: hostile $label input succeeded or escaped its time bound" >&2
		exit 1
	fi
}

hostile_sources="$fixture/hostile-sources"
mkdir -p "$hostile_sources"/{artifact-fifo,artifact-link,artifact-oversized}
valid_artifact="$fixture/assets/steward-control_v1.1.0_linux_${test_goarch}.tar.gz"
calls_before_sources=$(wc -l </run/fake-systemctl/calls)
mkfifo "$hostile_sources/checksums.fifo"
reject_hostile_local_source checksums-fifo "$valid_artifact" "$hostile_sources/checksums.fifo"
ln -s "$fixture/assets/checksums.txt" "$hostile_sources/checksums.link"
reject_hostile_local_source checksums-symlink "$valid_artifact" "$hostile_sources/checksums.link"
truncate -s 4194305 "$hostile_sources/checksums.oversized"
reject_hostile_local_source checksums-oversized "$valid_artifact" "$hostile_sources/checksums.oversized"
cp "$fixture/assets/checksums.txt" "$hostile_sources/checksums.growing"
truncate -s 4194304 "$hostile_sources/checksums.growing"
touch "$hostile_sources/grow"
(
	while [[ -e $hostile_sources/grow ]]; do
		truncate -s 4194305 "$hostile_sources/checksums.growing"
		truncate -s 4194304 "$hostile_sources/checksums.growing"
	done
) &
growth_pid=$!
reject_hostile_local_source checksums-growth "$valid_artifact" "$hostile_sources/checksums.growing"
rm -f "$hostile_sources/grow"
wait "$growth_pid"
hostile_artifact_name="steward-control_v1.1.0_linux_${test_goarch}.tar.gz"
mkfifo "$hostile_sources/artifact-fifo/$hostile_artifact_name"
reject_hostile_local_source artifact-fifo "$hostile_sources/artifact-fifo/$hostile_artifact_name" \
	"$fixture/assets/checksums.txt"
ln -s "$valid_artifact" "$hostile_sources/artifact-link/$hostile_artifact_name"
reject_hostile_local_source artifact-symlink "$hostile_sources/artifact-link/$hostile_artifact_name" \
	"$fixture/assets/checksums.txt"
truncate -s 268435457 "$hostile_sources/artifact-oversized/$hostile_artifact_name"
reject_hostile_local_source artifact-oversized "$hostile_sources/artifact-oversized/$hostile_artifact_name" \
	"$fixture/assets/checksums.txt"
unsafe_parent=/tmp/steward-control-unsafe-input
rm -rf "$unsafe_parent"
mkdir -m 0777 "$unsafe_parent"
cp "$valid_artifact" "$unsafe_parent/$hostile_artifact_name"
cp "$fixture/assets/checksums.txt" "$unsafe_parent/checksums.txt"
reject_hostile_local_source unsafe-parent "$unsafe_parent/$hostile_artifact_name" "$unsafe_parent/checksums.txt"
touch "$unsafe_parent/swap"
(
	while [[ -e $unsafe_parent/swap ]]; do
		mv "$unsafe_parent/checksums.txt" "$unsafe_parent/checksums.saved" 2>/dev/null || true
		printf '%s\n' malicious >"$unsafe_parent/checksums.txt"
		rm -f "$unsafe_parent/checksums.txt"
		mv "$unsafe_parent/checksums.saved" "$unsafe_parent/checksums.txt" 2>/dev/null || true
	done
) &
rename_flip_pid=$!
reject_hostile_local_source rename-flip "$unsafe_parent/$hostile_artifact_name" "$unsafe_parent/checksums.txt"
rm -f "$unsafe_parent/swap"
wait "$rename_flip_pid"
rm -rf "$unsafe_parent"
[[ $(wc -l </run/fake-systemctl/calls) -eq $calls_before_sources ]]
[[ -f /run/fake-systemctl/active ]]

list_bomb="$fixture/list-bomb"
mkdir -p "$list_bomb/stage" "$list_bomb/assets"
padding_name=highly-compressible-repeated-archive-padding-entry
printf x >"$list_bomb/stage/$padding_name"
for _ in {1..5000}; do printf '%s\n' "$padding_name"; done >"$list_bomb/members"
list_bomb_name="steward-control_v8.8.8_linux_${test_goarch}.tar.gz"
tar -C "$list_bomb/stage" -czf "$list_bomb/assets/$list_bomb_name" -T "$list_bomb/members"
(cd "$list_bomb/assets" && sha256sum "$list_bomb_name" >checksums.txt)
cat >"$list_bomb/tar-env-payload" <<'EOF'
#!/bin/sh
touch /tmp/steward-control-tar-options-executed
EOF
cat >"$list_bomb/bash-env-payload" <<'EOF'
touch /tmp/steward-control-bash-env-executed
EOF
chmod 0755 "$list_bomb/tar-env-payload"
rm -f /tmp/steward-control-tar-options-executed /tmp/steward-control-bash-env-executed \
	/tmp/steward-control-tar-function-executed
if (
	# shellcheck disable=SC2329 # Exported fixture must remain uncalled under Bash privileged mode.
	tar() { touch /tmp/steward-control-tar-function-executed; /usr/bin/tar "$@"; }
	export -f tar
	BASH_ENV="$list_bomb/bash-env-payload" \
		TAR_OPTIONS="--checkpoint=1 --checkpoint-action=exec=$list_bomb/tar-env-payload" GZIP=-v \
		timeout 15 /bin/bash -p /repo/scripts/install-control.sh --non-interactive --version v8.8.8 \
		--artifact "$list_bomb/assets/$list_bomb_name" --checksums "$list_bomb/assets/checksums.txt" \
		>/tmp/control-list-bomb.out 2>&1
); then
	list_bomb_status=0
else
	list_bomb_status=$?
fi
if (( list_bomb_status == 0 || list_bomb_status == 124 )); then
	echo "control-install-smoke: compressible archive-list bomb succeeded or escaped its time bound" >&2
	exit 1
fi
[[ ! -e /tmp/steward-control-tar-options-executed ]]
[[ ! -e /tmp/steward-control-bash-env-executed ]]
[[ ! -e /tmp/steward-control-tar-function-executed ]]
[[ $(wc -l </run/fake-systemctl/calls) -eq $calls_before_sources ]]
[[ -f /run/fake-systemctl/active ]]

reject_hostile_tls() {
	local key_path=$1 status
	if timeout 5 /bin/bash -p /repo/scripts/install-control.sh --non-interactive \
		--artifact "$fixture/assets/steward-control_v1.1.0_linux_${test_goarch}.tar.gz" \
		--checksums "$fixture/assets/checksums.txt" --version v1.1.0 \
		--addr 0.0.0.0:8443 --tls-cert /root/hostile-input.crt --tls-key "$key_path" \
		--admin-token-out /root/steward-control-admin.token \
		>/tmp/control-hostile-tls.out 2>&1; then
		status=0
	else
		status=$?
	fi
	(( status != 0 && status != 124 ))
}
printf '%s\n' not-a-certificate >/root/hostile-input.crt
chmod 0644 /root/hostile-input.crt
calls_before_tls=$(wc -l </run/fake-systemctl/calls)
mkfifo -m 0600 /root/hostile-input.fifo
reject_hostile_tls /root/hostile-input.fifo
rm /root/hostile-input.fifo
ln -s /root/hostile-input.crt /root/hostile-input.link
reject_hostile_tls /root/hostile-input.link
rm /root/hostile-input.link
truncate -s 1048577 /root/hostile-input.oversized
chmod 0600 /root/hostile-input.oversized
reject_hostile_tls /root/hostile-input.oversized
rm /root/hostile-input.oversized
mkdir -p /tmp/unsafe-steward-tls
printf '%s\n' key >/tmp/unsafe-steward-tls/tls.key
chmod 0600 /tmp/unsafe-steward-tls/tls.key
reject_hostile_tls /tmp/unsafe-steward-tls/tls.key
rm -rf /tmp/unsafe-steward-tls /root/hostile-input.crt
[[ $(wc -l </run/fake-systemctl/calls) -eq $calls_before_tls ]]
[[ -f /run/fake-systemctl/active ]]

printf '%s\n' snapshot-certificate >/root/snapshot-input.crt
printf '%s\n' snapshot-private-key >/root/snapshot-input.key
chmod 0644 /root/snapshot-input.crt
chmod 0600 /root/snapshot-input.key
snapshot_config_hash=$(sha256sum /etc/steward-control/control.env)
if /bin/bash -p /repo/scripts/install-control.sh --non-interactive \
	--artifact "$fixture/assets/steward-control_v1.2.0_linux_${test_goarch}.tar.gz" \
	--checksums "$fixture/assets/checksums.txt" --version v1.2.0 \
	--addr 0.0.0.0:8443 --tls-cert /root/snapshot-input.crt --tls-key /root/snapshot-input.key \
	--admin-token-out /root/steward-control-admin.token \
	>/tmp/control-snapshot-tls.out 2>&1; then
	echo "control-install-smoke: intentionally invalid TLS snapshot upgrade unexpectedly succeeded" >&2
	exit 1
fi
[[ $(sha256sum /etc/steward-control/control.env) == "$snapshot_config_hash" ]]
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
[[ -f /run/fake-systemctl/active && ! -e /etc/steward-control/tls.crt && ! -e /etc/steward-control/tls.key ]]
rm /root/snapshot-input.crt /root/snapshot-input.key

if install_version v1.2.0 >/tmp/control-failure.out 2>&1; then
	echo "control-install-smoke: invalid upgrade unexpectedly succeeded" >&2
	exit 1
fi
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
[[ -f /run/fake-systemctl/active ]]
[[ $(sha256sum /root/steward-control-admin.token) == "$token_hash" ]]

touch /run/fake-systemctl/fail-next-restart
if install_version v1.3.0 >/tmp/control-start-failure.out 2>&1; then
	echo "control-install-smoke: failed service activation unexpectedly succeeded" >&2
	exit 1
fi
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
[[ -f /run/fake-systemctl/active ]]
tail -10 /run/fake-systemctl/calls | grep -Fxq 'stop steward-control.service'
tail -10 /run/fake-systemctl/calls | grep -Fxq 'start steward-control.service'

config_hash=$(sha256sum /etc/steward-control/control.env)
truncate -s 1048577 /etc/steward-control/tls.key
chown steward-control:steward-control /etc/steward-control/tls.key
chmod 0600 /etc/steward-control/tls.key
if install_version v1.3.0 >/tmp/control-oversized-existing-tls.out 2>&1; then
	echo "control-install-smoke: oversized service-owned TLS key was backed up or adopted" >&2
	exit 1
fi
[[ $(stat -c '%s:%U:%G:%a' /etc/steward-control/tls.key) == '1048577:steward-control:steward-control:600' ]]
[[ $(sha256sum /etc/steward-control/control.env) == "$config_hash" ]]
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]
[[ -f /run/fake-systemctl/active ]]
rm /etc/steward-control/tls.key

mkdir -p "$fixture/tampered"
cp "$fixture/assets/steward-control_v1.1.0_linux_${test_goarch}.tar.gz" \
	"$fixture/tampered/steward-control_v1.1.0_linux_${test_goarch}.tar.gz"
printf x >>"$fixture/tampered/steward-control_v1.1.0_linux_${test_goarch}.tar.gz"
if /bin/bash -p /repo/scripts/install-control.sh --non-interactive \
	--artifact "$fixture/tampered/steward-control_v1.1.0_linux_${test_goarch}.tar.gz" --checksums "$fixture/assets/checksums.txt" \
	--version v1.1.0 >/tmp/control-tamper.out 2>&1; then
	echo "control-install-smoke: tampered artifact unexpectedly succeeded" >&2
	exit 1
fi
[[ $(readlink /opt/steward-control/current) == /opt/steward-control/releases/v1.1.0 ]]

if /bin/bash -p /repo/scripts/install-control.sh --non-interactive --dry-run --version v1.1.0 \
	--addr 0.0.0.0:8443 >/tmp/control-remote.out 2>&1; then
	echo "control-install-smoke: remote plaintext listener unexpectedly succeeded" >&2
	exit 1
fi
long_listener="$(printf 'a%.0s' {1..513}):1"
for unsafe_address in 'control#host:8443' 'control"host:8443' 'control\host:8443' $'control\nhost:8443' \
	'127.0.0.1:18446744073709551617' '127.0000.0.1:8443' "$long_listener"; do
	if /bin/bash -p /repo/scripts/install-control.sh --non-interactive --dry-run --version v1.1.0 \
		--addr "$unsafe_address" >/tmp/control-address.out 2>&1; then
		echo "control-install-smoke: unsafe listener address unexpectedly succeeded" >&2
		exit 1
	fi
	grep -Fq -- '--addr must be a valid HOST:PORT' /tmp/control-address.out
done
if /bin/bash -p /repo/scripts/install-control.sh --non-interactive --dry-run --version v1.1.0 \
	--admin-token-out /root/.steward-control-admin-token.reserved \
	>/tmp/control-reserved-token-path.out 2>&1; then
	echo "control-install-smoke: reserved token publication namespace was accepted as an output" >&2
	exit 1
fi
grep -Fq 'reserved temporary-file namespace' /tmp/control-reserved-token-path.out
long_release="v1.2.3-$(printf 'a%.0s' {1..122})"
if /bin/bash -p /repo/scripts/install-control.sh --non-interactive --dry-run --version "$long_release" \
	>/tmp/control-long-release.out 2>&1; then
	echo "control-install-smoke: overlong release version was accepted" >&2
	exit 1
fi
grep -Fq 'version must be latest or a vX.Y.Z release tag' /tmp/control-long-release.out

if /bin/bash -p /repo/scripts/control-doctor.sh --json --probe-url $'https://control.example\n.invalid' \
	>/tmp/control-doctor-url.out 2>&1; then
	echo "control-install-smoke: control doctor accepted whitespace in a probe URL" >&2
	exit 1
fi
truncate -s 1048577 "$fixture/oversized-ca.pem"
if /bin/bash -p /repo/scripts/control-doctor.sh --json --ca-file "$fixture/oversized-ca.pem" \
	>/tmp/control-doctor-ca.out 2>&1; then
	echo "control-install-smoke: control doctor accepted an oversized CA file" >&2
	exit 1
fi

unit=/repo/deploy/systemd/steward-control.service
for setting in 'User=steward-control' 'Group=steward-control' 'UMask=0077' \
	'NoNewPrivileges=yes' 'CapabilityBoundingSet=' 'ProtectSystem=strict' \
	'RestrictNamespaces=yes' 'StateDirectoryMode=0700' 'LimitNOFILE=4096' \
	'MemoryMax=1G' 'MemorySwapMax=0'; do
	grep -Fxq "$setting" "$unit"
done
if grep -Eiq 'docker|SupplementaryGroups' "$unit"; then
	echo "control-install-smoke: controller unit carries Docker authority" >&2
	exit 1
fi

# Finish with the actual Linux control binary, not only the transactional test
# double. This catches initialization, secure-file metadata, and check-config
# drift under the dedicated service identity.
rm -rf /var/lib/steward-control /etc/steward-control /opt/steward-control \
	/usr/local/libexec/steward-control /root/steward-control-admin.token
rm -f /usr/local/bin/steward-control /etc/systemd/system/steward-control.service
userdel steward-control
groupdel steward-control 2>/dev/null || true
rm -rf /run/fake-systemctl/*
real_stage="$fixture/real-v9.9.0"
mkdir -p "$real_stage" "$fixture/real-assets"
cp /real/steward-control "$real_stage/steward-control"
cp /repo/deploy/config/control.env "$real_stage/control.env"
cp /repo/deploy/systemd/steward-control.service "$real_stage/steward-control.service"
cp /repo/scripts/control-doctor.sh "$real_stage/control-doctor.sh"
cp /repo/LICENSE "$real_stage/LICENSE"
tar -C "$real_stage" -czf "$fixture/real-assets/steward-control_v9.9.0_linux_${test_goarch}.tar.gz" \
	LICENSE control.env control-doctor.sh steward-control steward-control.service
(cd "$fixture/real-assets" && sha256sum ./*.tar.gz >checksums.txt)
install_real() {
	/bin/bash -p /repo/scripts/install-control.sh --non-interactive --no-start --version v9.9.0 \
		--artifact "$fixture/real-assets/steward-control_v9.9.0_linux_${test_goarch}.tar.gz" \
		--checksums "$fixture/real-assets/checksums.txt" \
		--admin-token-out /root/steward-control-admin.token
}
install_real
[[ $(/usr/local/bin/steward-control -version) == 'steward-control v9.9.0' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control) == 'steward-control:steward-control 700' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/witness.private.pem) == 'steward-control:steward-control 600' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/witness.public.pem) == 'steward-control:steward-control 644' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/controller.private.pem) == 'steward-control:steward-control 600' ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control/controller.public.pem) == 'steward-control:steward-control 644' ]]
[[ $(stat -c '%U:%G %a' /root/steward-control-admin.token) == 'root:root 600' ]]
[[ $(stat -c '%h' /root/steward-control-admin.token) == 1 ]]
if find /root -maxdepth 1 -name "$publication_pattern" -print -quit | grep -q .; then
	echo "control-install-smoke: temporary admin token publication file was not removed" >&2
	exit 1
fi
real_token_hash=$(sha256sum /root/steward-control-admin.token)
real_witness_hash=$(sha256sum /var/lib/steward-control/witness.private.pem \
	/var/lib/steward-control/witness.public.pem)
real_controller_hash=$(sha256sum /var/lib/steward-control/controller.private.pem \
	/var/lib/steward-control/controller.public.pem)
ln /root/steward-control-admin.token "${publication_prefix}interrupted-link"
install_real >/dev/null
[[ ! -e ${publication_prefix}interrupted-link ]]
[[ $(stat -c '%h' /root/steward-control-admin.token) == 1 ]]
[[ $(sha256sum /var/lib/steward-control/witness.private.pem \
	/var/lib/steward-control/witness.public.pem) == "$real_witness_hash" ]]
[[ $(sha256sum /var/lib/steward-control/controller.private.pem \
	/var/lib/steward-control/controller.public.pem) == "$real_controller_hash" ]]

cp -p /root/steward-control-admin.token "${publication_prefix}interrupted-temp"
rm /root/steward-control-admin.token
install_real
[[ $(sha256sum /root/steward-control-admin.token) == "$real_token_hash" ]]
[[ ! -e ${publication_prefix}interrupted-temp ]]
grep -Fxq unrelated-token-sentinel "$unrelated_sentinel"

chown -hR root:root /var/lib/steward-control
rm /root/steward-control-admin.token
install_real
[[ $(sha256sum /root/steward-control-admin.token) == "$real_token_hash" ]]
[[ $(stat -c '%U:%G %a' /var/lib/steward-control) == 'steward-control:steward-control 700' ]]

cp -p /root/steward-control-admin.token "$fixture/real-admin.token"
printf '%s\n' steward_cp_v1_stale_bootstrap >/root/steward-control-admin.token
if install_real >/tmp/control-stale-token.out 2>&1; then
	echo "control-install-smoke: stale bootstrap token unexpectedly passed authenticated proof" >&2
	exit 1
fi
grep -Fxq steward_cp_v1_stale_bootstrap /root/steward-control-admin.token
rm /root/steward-control-admin.token
install -m 0600 -o root -g root "$fixture/real-admin.token" /root/steward-control-admin.token

runuser -u steward-control -- /usr/local/bin/steward-control -check-config \
	-state-dir /var/lib/steward-control -auth-key-file /var/lib/steward-control/auth.key >/dev/null
runuser -u steward-control -- /usr/local/bin/steward-control \
	-state-dir /var/lib/steward-control -auth-key-file /var/lib/steward-control/auth.key \
	>/tmp/real-control.stdout 2>/tmp/real-control.stderr &
real_pid=$!
real_ready=false
for _ in {1..40}; do
	if curl --fail --silent --max-time 1 http://127.0.0.1:8443/v1/readiness | grep -Fq '"status":"ready"'; then real_ready=true; break; fi
	sleep 0.1
done
[[ $real_ready == true ]]
touch /run/fake-systemctl/active
doctor_json=$(/usr/local/libexec/steward-control/control-doctor --json)
[[ $doctor_json == *'"status":"ok"'* && $doctor_json == *'"failures":0'* ]]
printf 'Authorization: Bearer ' >"$fixture/admin.header"
cat /root/steward-control-admin.token >>"$fixture/admin.header"
create_status=$(curl -q --noproxy '*' --proto '=http' --max-redirs 0 --silent --show-error \
	--max-time 5 --max-filesize 4096 --header "@$fixture/admin.header" \
	--header 'Content-Type: application/json' --data '{"tenant_id":"smoke-tenant"}' \
	--output "$fixture/create-tenant.json" --write-out '%{http_code}' \
	http://127.0.0.1:8443/v1/tenants)
[[ $create_status == 201 ]]
rm -f "$fixture/admin.header"
kill -TERM "$real_pid"
wait "$real_pid" || true

populated_state_hash=$(find /var/lib/steward-control -maxdepth 1 -type f -exec sha256sum {} + | sort)
cp -p /root/steward-control-admin.token "$fixture/populated-admin.token"
rm /root/steward-control-admin.token
if install_real >/tmp/control-populated-recovery.out 2>&1; then
	echo "control-install-smoke: populated state unexpectedly reproduced a missing bootstrap token" >&2
	exit 1
fi
[[ ! -e /root/steward-control-admin.token ]]
[[ $(find /var/lib/steward-control -maxdepth 1 -type f -exec sha256sum {} + | sort) == "$populated_state_hash" ]]
install -m 0600 -o root -g root "$fixture/populated-admin.token" /root/steward-control-admin.token
install_real >/dev/null
grep -Fxq unrelated-token-sentinel "$unrelated_sentinel"

echo "control-install-smoke: offline install, rollback, hardening, authenticated bootstrap recovery, and refusal passed"
