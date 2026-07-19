#!/usr/bin/env bash
# Build the exact committed OpenClaw adapter into one atomically published bundle.
set -euo pipefail
umask 077
unset CDPATH NODE_OPTIONS OPENCLAW_IMAGE OPENCLAW_SOURCE_REVISION
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

root=
script_path=
readonly expected_repository=https://github.com/openclaw/openclaw.git
readonly expected_release=v2026.7.1
readonly expected_revision=2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4
readonly base_image=ghcr.io/openclaw/openclaw:2026.7.1@sha256:6a31d44b2944e7adcd2b582bf6fb463111264ebca97a0201795b799135bd102c
readonly base_amd64_manifest=sha256:165b4992f1b4b74ffdd7a02c887ba006f9f5dc951eca420eef573a8b233b543f
readonly default_build_timeout=1800
readonly default_pull_timeout=900
readonly default_save_timeout=900
readonly default_max_archive_bytes=$((4 * 1024 * 1024 * 1024))
readonly default_min_free_bytes=$((6 * 1024 * 1024 * 1024))

output=
keep_image=false
build_timeout=$default_build_timeout
pull_timeout=$default_pull_timeout
save_timeout=$default_save_timeout
max_archive_bytes=$default_max_archive_bytes
min_free_bytes=$default_min_free_bytes

usage() {
	cat <<'USAGE'
Usage:
  scripts/build-openclaw-adapter.sh --output DIRECTORY [options]

Builds the committed, pinned OpenClaw adapter for Linux on amd64. The output is
one new directory containing image.tar and attestation.json. Publication is one
atomic directory rename, so an interrupted build cannot expose half a bundle.

Options:
  --output DIRECTORY       New bundle directory (required)
  --non-interactive        Compatibility flag; this builder never prompts
  --keep-image             Keep the temporary local image tag
  --build-timeout SEC      Docker build timeout (300..3600; default 1800)
  --pull-timeout SEC       Pinned base-image pull timeout (30..1800; default 900)
  --save-timeout SEC       Docker save timeout (30..1800; default 900)
  --max-archive-bytes N    Refuse a larger image archive (1 GiB..16 GiB)
  --min-free-bytes N       Required free space (2 GiB..1 TiB)
  -h, --help               Show this help

The base image pull is the only networked build step. Docker executes the
adapter Dockerfile with --network=none and uses only the exact committed adapter
tree plus the digest-pinned official OpenClaw release image.
USAGE
}

die() {
	echo "build-openclaw-adapter: $*" >&2
	exit 1
}

usage_error() {
	echo "build-openclaw-adapter: $*" >&2
	usage >&2
	exit 2
}

progress() {
	echo "==> $*" >&2
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

inspect_image_archive() {
	local archive=$1
	if command -v stewardctl >/dev/null 2>&1; then
		stewardctl image inspect -archive "$archive"
		return
	fi
	local go_binary=
	if command -v go >/dev/null 2>&1; then
		go_binary=$(command -v go)
	elif [[ -x /usr/local/go/bin/go ]]; then
		go_binary=/usr/local/go/bin/go
	fi
	[[ -n $go_binary ]] || die "stewardctl or Go 1.24+ is required to verify the saved OCI archive"
	(
		cd "$root"
		env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off "$go_binary" run ./cmd/stewardctl image inspect -archive "$archive"
	)
}

integer_range() {
	local name=$1 value=$2 minimum=$3 maximum=$4
	[[ $value =~ ^[1-9][0-9]{0,15}$ ]] || usage_error "$name must be a canonical positive integer"
	local decimal=$((10#$value))
	(( decimal >= minimum && decimal <= maximum )) || usage_error "$name must be between $minimum and $maximum"
}

while (( $# > 0 )); do
	case $1 in
	--output)
		(( $# >= 2 )) || usage_error "--output requires a value"
		output=$2
		shift 2
		;;
	--non-interactive)
		shift
		;;
	--keep-image)
		keep_image=true
		shift
		;;
	--build-timeout | --pull-timeout | --save-timeout | --max-archive-bytes | --min-free-bytes)
		(( $# >= 2 )) || usage_error "$1 requires a value"
		case $1 in
		--build-timeout) build_timeout=$2 ;;
		--pull-timeout) pull_timeout=$2 ;;
		--save-timeout) save_timeout=$2 ;;
		--max-archive-bytes) max_archive_bytes=$2 ;;
		--min-free-bytes) min_free_bytes=$2 ;;
		esac
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) usage_error "unknown option: $1" ;;
	esac
done

[[ -n $output ]] || usage_error "--output is required"
integer_range --build-timeout "$build_timeout" 300 3600
integer_range --pull-timeout "$pull_timeout" 30 1800
integer_range --save-timeout "$save_timeout" 30 1800
integer_range --max-archive-bytes "$max_archive_bytes" $((1024 * 1024 * 1024)) $((16 * 1024 * 1024 * 1024))
integer_range --min-free-bytes "$min_free_bytes" $((2 * 1024 * 1024 * 1024)) $((1024 * 1024 * 1024 * 1024))
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die "the qualified build platform is Linux on amd64"
for command in docker python3 sha256sum timeout tar readlink; do require_command "$command"; done
script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
root=$(cd "$(dirname "$script_path")/.." && pwd -P)

output_parent=$(dirname "$output")
output_name=$(basename "$output")
[[ $output_name != . && $output_name != .. && $output_name != */* ]] || usage_error "--output must name a directory"
python3 -I - "$output_parent" "$output" <<'PY' || die "output parent is unsafe or output already exists"
import os
import pathlib
import stat
import sys

parent = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
info = os.lstat(parent)
if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit(1)
if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
    raise SystemExit(1)
try:
    os.lstat(output)
except FileNotFoundError:
    pass
else:
    raise SystemExit(1)
PY

adapter_source=
adapter_path=$root/adapters/openclaw
adapter_commit=unavailable
adapter_tree=unavailable
release_version=unavailable
release_manifest_sha256=unavailable
checkout=
if command -v git >/dev/null 2>&1; then
	checkout=$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || true)
fi
if [[ $checkout == "$root" ]]; then
	adapter_source=git-checkout
	adapter_commit=$(git -C "$root" rev-parse HEAD)
	adapter_tree=$(git -C "$root" rev-parse "HEAD:adapters/openclaw" 2>/dev/null || true)
	[[ $adapter_commit =~ ^[a-f0-9]{40,64}$ && $adapter_tree =~ ^[a-f0-9]{40,64}$ ]] || die "committed adapter identity is unavailable"
	git -C "$root" diff --quiet -- adapters/openclaw || die "adapters/openclaw has uncommitted changes"
	git -C "$root" diff --cached --quiet -- adapters/openclaw || die "adapters/openclaw has staged changes"
	git -C "$root" diff --quiet -- scripts/build-openclaw-adapter.sh || die "builder has uncommitted changes"
	git -C "$root" diff --cached --quiet -- scripts/build-openclaw-adapter.sh || die "builder has staged changes"
elif [[ -f $root/release.json && -d $adapter_path ]]; then
	adapter_source=release-payload
	release_manifest=$root/release.json
elif [[ -f $(dirname "$root")/release.json && -d $adapter_path ]]; then
	adapter_source=release-payload
	release_manifest=$(dirname "$root")/release.json

else
	die "OpenClaw adapter is absent from a committed checkout or verified release payload"
fi
if [[ $adapter_source == release-payload ]]; then
	release_values=$(python3 -I - "$adapter_path" "$script_path" "$release_manifest" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

adapter, script, manifest_path = map(pathlib.Path, sys.argv[1:])
if manifest_path.stat().st_size > 1 << 20:
    raise SystemExit(1)
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
files = manifest.get("files") if isinstance(manifest, dict) else None
version = manifest.get("version") if isinstance(manifest, dict) else None
if (
    manifest.get("schema") != "steward.release.v2"
    or manifest.get("os") != "linux"
    or not isinstance(files, dict)
    or not isinstance(version, str)
    or re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version) is None
):
    raise SystemExit(1)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

actual = set()
for path in sorted(adapter.rglob("*")):
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode):
        continue
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(1)
    actual.add("integration/adapters/openclaw/" + path.relative_to(adapter).as_posix())
expected = {name for name in files if name.startswith("integration/adapters/openclaw/")}
if actual != expected:
    raise SystemExit(1)
for name in actual:
    path = adapter / name.removeprefix("integration/adapters/openclaw/")
    if digest(path) != files.get(name):
        raise SystemExit(1)
builder_name = "integration/scripts/build-openclaw-adapter.sh"
if digest(script) != files.get(builder_name):
    raise SystemExit(1)
print(version)
print(digest(manifest_path))
PY
	) || die "packaged OpenClaw adapter differs from release.json"
	mapfile -t release_fields <<<"$release_values"
	(( ${#release_fields[@]} == 2 )) || die "packaged release identity is incomplete"
	release_version=${release_fields[0]}
	release_manifest_sha256=${release_fields[1]}
fi

work=$(mktemp -d /tmp/steward-openclaw-build.XXXXXX)
staging=$output_parent/.${output_name}.steward-build-$$
image_tag=unavailable
cleanup() {
	rm -rf "$work" "$staging"
	if [[ $keep_image != true ]]; then
		docker image rm "$image_tag" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

available_kib=$(df -Pk -- "$output_parent" | awk 'NR == 2 { print $4 }')
[[ $available_kib =~ ^[0-9]+$ ]] || die "could not determine output free space"
(( available_kib * 1024 >= min_free_bytes )) || die "output filesystem has less than $min_free_bytes free bytes"

mkdir -m 0700 "$work/context"
if [[ $adapter_source == git-checkout ]]; then
	git -C "$root" archive "$adapter_commit:adapters/openclaw" | tar -xf - -C "$work/context"
else
	(cd "$adapter_path" && tar -cf - .) | tar -xf - -C "$work/context"
fi
(
	cd "$work/context"
	sha256sum -c source-inputs.sha256
) >/dev/null || die "committed adapter source inventory is invalid"
source_manifest_sha256=$(sha256sum "$work/context/source-inputs.sha256" | awk '{print $1}')
adapter_identity=$adapter_tree
[[ $adapter_identity == unavailable ]] && adapter_identity=$source_manifest_sha256
image_tag=steward-openclaw-adapter:source-${adapter_identity:0:12}

progress "Pulling the exact upstream image"
timeout "$pull_timeout" docker pull "$base_image" >/dev/null || die "pinned base-image pull failed"
progress "Building with Docker network disabled"
DOCKER_BUILDKIT=1 timeout "$build_timeout" docker build \
	--network=none --pull=false --platform=linux/amd64 --provenance=false \
	--build-arg "OPENCLAW_IMAGE=$base_image" \
	--build-arg "OPENCLAW_SOURCE_REVISION=$expected_revision" \
	-t "$image_tag" "$work/context" >/dev/null || die "adapter image build failed"

runtime_image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
image_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_tag")
image_user=$(docker image inspect --format '{{.Config.User}}' "$image_tag")
image_volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$image_tag")
[[ $runtime_image_id =~ ^sha256:[a-f0-9]{64}$ && $image_platform == linux/amd64 ]] || die "built image identity is invalid"
[[ $image_user == 65532:65532 ]] || die "built image is not configured for 65532:65532"
[[ $image_volumes == null || $image_volumes == '{}' ]] || die "built image declares an unmanaged volume"

mkdir -m 0700 "$staging"
progress "Saving the offline image archive"
timeout "$save_timeout" docker save --output "$staging/image.tar" "$image_tag" || die "Docker image save failed"
chmod 0600 "$staging/image.tar"
archive_bytes=$(stat -c %s "$staging/image.tar")
[[ $archive_bytes =~ ^[1-9][0-9]*$ ]] || die "archive size is invalid"
(( archive_bytes <= max_archive_bytes )) || die "archive exceeds $max_archive_bytes bytes"
archive_sha256=$(sha256sum "$staging/image.tar" | awk '{print $1}')
builder_sha256=$(sha256sum "$root/scripts/build-openclaw-adapter.sh" | awk '{print $1}')
archive_image_json=$(inspect_image_archive "$staging/image.tar") || die "saved OCI archive failed Steward inspection"
archive_image_values=$(python3 -I - "$archive_image_json" "$image_tag" "$runtime_image_id" <<'PY'
import json
import re
import sys

payload = json.loads(sys.argv[1])
digest = re.compile(r"sha256:[a-f0-9]{64}")
manifest = payload.get("manifest_digest")
config = payload.get("config_digest")
platform = payload.get("platform", {})
if (
    digest.fullmatch(manifest or "") is None
    or digest.fullmatch(config or "") is None
    or sys.argv[3] not in {manifest, config}
    or payload.get("repo_tags") != [sys.argv[2]]
    or platform != {"architecture": "amd64", "os": "linux"}
):
    raise SystemExit(1)
print(manifest)
print(config)
PY
) || die "saved OCI archive identity is invalid"
mapfile -t archive_image_fields <<<"$archive_image_values"
(( ${#archive_image_fields[@]} == 2 )) || die "saved OCI archive identity is incomplete"
image_manifest_digest=${archive_image_fields[0]}
image_config_digest=${archive_image_fields[1]}

python3 -I - "$staging/attestation.json" "$archive_bytes" "$archive_sha256" \
	"$image_tag" "$image_manifest_digest" "$image_config_digest" "$runtime_image_id" \
	"$adapter_source" "$adapter_commit" "$adapter_tree" "$release_version" "$release_manifest_sha256" \
	"$source_manifest_sha256" "$builder_sha256" "$expected_repository" \
	"$expected_release" "$expected_revision" "$base_image" "$base_amd64_manifest" <<'PY'
import json
import os
import pathlib
import sys

(
    output, archive_bytes, archive_sha256, image_tag, image_manifest, image_config,
    runtime_image_id, adapter_source, adapter_commit, adapter_tree, release_version,
    release_manifest_sha256, source_manifest, builder_sha256,
    repository, release, revision, base_image, base_amd64_manifest,
) = sys.argv[1:]
adapter = {
    "contract": "steward.openclaw.v1",
    "source": adapter_source,
    "source_inventory_sha256": source_manifest,
}
if adapter_source == "git-checkout":
    adapter.update({"git_tree": adapter_tree, "steward_commit": adapter_commit})
else:
    adapter.update({"release_manifest_sha256": release_manifest_sha256, "release_version": release_version})
payload = {
    "adapter": adapter,
    "archive": {
        "bytes": int(archive_bytes),
        "file": "image.tar",
        "sha256": archive_sha256,
    },
    "build_recipe": {
        "builder_sha256": builder_sha256,
        "id": "steward.openclaw-adapter.docker-build.v1",
        "network_scope": "pinned-base-pull;docker-build-network-none",
        "platform": "linux/amd64",
    },
    "contains_agent_content": False,
    "image": {
        "config_digest": image_config,
        "manifest_digest": image_manifest,
        "runtime_image_id": runtime_image_id,
        "tag": image_tag,
        "user": "65532:65532",
    },
    "schema_version": "steward.openclaw-adapter-build-attestation.v1",
    "source": {
        "base_image": base_image,
        "base_linux_amd64_manifest_digest": base_amd64_manifest,
        "release": release,
        "repository": repository,
        "revision": revision,
    },
}
path = pathlib.Path(output)
with path.open("x", encoding="utf-8") as stream:
    json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(path, 0o600)
for candidate in (path.parent / "image.tar", path):
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY

python3 -I - "$staging" "$output" <<'PY' || die "atomic bundle publication failed"
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
os.rename(source, destination)
parent = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY

trap - EXIT
cleanup
echo "$output"
