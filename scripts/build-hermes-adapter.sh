#!/usr/bin/env bash
# Build the exact pinned Hermes adapter into a new Docker image archive.
# This is a build-time tool. It never starts the resulting image and records no
# prompts, responses, secrets, or other agent content.
set -euo pipefail
umask 077
unset CDPATH PYTHONHOME PYTHONPATH
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly expected_repository=https://github.com/NousResearch/hermes-agent.git
readonly expected_revision=095b9eed3801c251796df93f48a8f2a527ff6e70
readonly default_build_timeout=3600
readonly default_clone_timeout=600
readonly default_save_timeout=900
readonly default_min_free_bytes=$((4 * 1024 * 1024 * 1024))
readonly default_max_archive_bytes=$((8 * 1024 * 1024 * 1024))
readonly sandbox_memory_bytes=$((4 * 1024 * 1024 * 1024))
readonly sandbox_output_bytes=$((2 * 1024 * 1024 * 1024))
readonly wheelhouse_max_bytes=$((1024 * 1024 * 1024))
readonly wheelhouse_max_file_bytes=$((512 * 1024 * 1024))
readonly wheelhouse_max_files=512
readonly sandbox_pids=512
readonly sandbox_cpus=1

usage() {
	cat <<'USAGE'
Usage:
  scripts/build-hermes-adapter.sh [options]

Builds Steward's exact pinned Hermes adapter and publishes a new .tar archive
plus a canonical, metadata-only .attestation.json sidecar. The qualified build
platform is Linux on amd64.

Options:
  --output FILE.tar       New archive to create (required in non-interactive mode)
  --source-dir DIR        Use an already-present exact checkout; no source download
  --non-interactive       Do not prompt; fail if required input is missing
  --keep-image            Keep the temporary local Docker image after saving
  --build-timeout SEC     Docker build timeout (300..14400; default 3600)
  --clone-timeout SEC     Online fetch timeout (30..3600; default 600)
  --save-timeout SEC      Docker save timeout (30..3600; default 900)
  --min-free-bytes BYTES  Required free host space (1 GiB..1 TiB; default 4 GiB)
  --max-archive-bytes N   Refuse an archive over this size (1 GiB..64 GiB; default 8 GiB)
  -h, --help              Show this help

Without --source-dir, the builder fetches only the pinned upstream commit into a
temporary directory. A non-executing host fetcher downloads hash- and size-bound
Linux wheels named by the verified lockfile. Upstream build hooks then run with
no network inside a bounded gVisor sandbox with read-only inputs and no Docker
socket. The resulting runtime is not started and is suitable for offline import
and execution.
USAGE
}

die() {
	echo "build-hermes-adapter: $*" >&2
	exit 1
}

usage_error() {
	echo "build-hermes-adapter: $*" >&2
	usage >&2
	exit 2
}

progress() {
	echo "==> $*" >&2
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

safe_git() {
	local repository=$1
	shift
	env -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CEILING_DIRECTORIES \
		-u GIT_COMMON_DIR -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS -u GIT_DIR \
		-u GIT_EXEC_PATH -u GIT_INDEX_FILE -u GIT_NAMESPACE -u GIT_OBJECT_DIRECTORY \
		-u GIT_SHALLOW_FILE -u GIT_TEMPLATE_DIR -u GIT_WORK_TREE \
		GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
		git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c tar.umask=0022 -C "$repository" "$@"
}

safe_git_timeout() {
	local duration=$1 repository=$2
	shift 2
	timeout "$duration" env -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CEILING_DIRECTORIES \
		-u GIT_COMMON_DIR -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS -u GIT_DIR \
		-u GIT_EXEC_PATH -u GIT_INDEX_FILE -u GIT_NAMESPACE -u GIT_OBJECT_DIRECTORY \
		-u GIT_SHALLOW_FILE -u GIT_TEMPLATE_DIR -u GIT_WORK_TREE \
		GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
		git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c tar.umask=0022 -C "$repository" "$@"
}

validate_integer_range() {
	local name=$1 value=$2 minimum=$3 maximum=$4
	[[ $value =~ ^[1-9][0-9]{0,15}$ ]] || usage_error "$name must be a canonical positive integer"
	local decimal=$((10#$value))
	(( decimal >= minimum && decimal <= maximum )) || usage_error "$name must be between $minimum and $maximum"
}

sha256_file() {
	python3 -I - "$1" <<'PY'
import hashlib
import pathlib
import sys

digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

file_size() {
	python3 -I - "$1" <<'PY'
import os
import sys
print(os.stat(sys.argv[1], follow_symlinks=False).st_size)
PY
}

canonical_file_set_digest() {
	python3 -I - "$1" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
entries = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix()
    info = os.lstat(path)
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        continue
    if stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"mode": mode, "path": relative, "sha256": digest, "type": "file"})
    elif stat.S_ISLNK(info.st_mode):
        entries.append({"mode": mode, "path": relative, "target": os.readlink(path), "type": "symlink"})
    else:
        raise SystemExit(f"unsupported adapter entry type: {relative}")
encoded = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
print(hashlib.sha256(encoded).hexdigest())
PY
}

check_free_space() {
	local path=$1 label=$2 available_kib available_bytes
	available_kib=$(df -Pk -- "$path" | awk 'NR == 2 { print $4 }')
	[[ $available_kib =~ ^[0-9]+$ ]] || die "could not determine free space for $label"
	available_bytes=$((available_kib * 1024))
	(( available_bytes >= min_free_bytes )) || die "$label has $available_bytes free bytes; at least $min_free_bytes are required"
}

# Keep this function self-contained: the focused adapter fixture test executes
# this exact block to simulate stops at each publication boundary.
# BEGIN HERMES_PUBLICATION_PAIR
hermes_publication_pair() {
	python3 -I - "$@" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

operation = sys.argv[1]
archive = pathlib.Path(sys.argv[2])
metadata = pathlib.Path(sys.argv[3])
staging = pathlib.Path(sys.argv[4])
maximum = int(sys.argv[5])
(
    expected_repository,
    expected_revision,
    expected_adapter_source,
    expected_steward_commit,
    expected_adapter_tree,
    expected_release_version,
    expected_release_manifest,
    expected_builder,
) = sys.argv[6:]
if archive.parent != metadata.parent or archive.parent != staging.parent:
    raise SystemExit("publication paths must share one directory")
if maximum <= 0:
    raise SystemExit("publication archive limit is invalid")

parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open(archive.parent, parent_flags)


def named_stat(directory_fd, name):
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def identity(info):
    return info.st_dev, info.st_ino


def version(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def require_file(info, links):
    if (
        info is None
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != links
    ):
        raise SystemExit("publication contains an unsafe file")


def read_file(directory_fd, name, maximum_bytes):
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum_bytes:
            raise SystemExit("publication contains an invalid file")
        content = bytearray()
        while len(content) <= maximum_bytes:
            chunk = os.read(descriptor, min(1 << 20, maximum_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if len(content) != before.st_size or len(content) > maximum_bytes or version(before) != version(after) or version(after) != version(named):
            raise SystemExit("publication file changed while being read")
        return bytes(content), after
    finally:
        os.close(descriptor)


def hash_file(directory_fd, name, maximum_bytes):
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum_bytes:
            raise SystemExit("publication archive size is invalid")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise SystemExit("publication archive exceeds its limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if observed != before.st_size or version(before) != version(after) or version(after) != version(named):
            raise SystemExit("publication archive changed while being hashed")
        return digest.hexdigest(), after
    finally:
        os.close(descriptor)


def validate_pair(archive_fd, metadata_fd, archive_entry=None, metadata_entry=None):
    archive_entry = archive.name if archive_entry is None else archive_entry
    metadata_entry = metadata.name if metadata_entry is None else metadata_entry
    encoded, metadata_info = read_file(metadata_fd, metadata_entry, 64 << 10)
    try:
        document = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise SystemExit("publication attestation is invalid JSON") from error
    canonical = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    archive_record = document.get("archive") if isinstance(document, dict) else None
    image = document.get("image") if isinstance(document, dict) else None
    source = document.get("source") if isinstance(document, dict) else None
    adapter = document.get("adapter") if isinstance(document, dict) else None
    recipe = document.get("build_recipe") if isinstance(document, dict) else None
    if (
        encoded != canonical
        or document.get("schema_version") != "steward.hermes-adapter-build-attestation.v1"
        or document.get("contains_agent_content") is not False
        or not isinstance(archive_record, dict)
        or archive_record.get("file") != archive.name
        or not isinstance(image, dict)
        or not isinstance(source, dict)
        or source.get("repository") != expected_repository
        or source.get("revision") != expected_revision
        or not isinstance(adapter, dict)
        or adapter.get("contract") != "steward.hermes-agent.v1"
        or adapter.get("source") != expected_adapter_source
        or not isinstance(recipe, dict)
        or recipe.get("id") != "steward.hermes-adapter.docker-build.v1"
        or recipe.get("builder_sha256") != expected_builder
        or recipe.get("network_scope") != "verified-host-wheel-fetch;gvisor-hooks-network-none"
    ):
        raise SystemExit("publication attestation contract is invalid")
    if expected_adapter_source == "git-checkout":
        if (
            adapter.get("steward_commit") != expected_steward_commit
            or adapter.get("git_tree") != expected_adapter_tree
            or expected_release_version
            or expected_release_manifest
        ):
            raise SystemExit("publication attestation does not bind the current Steward commit")
    elif expected_adapter_source == "release-payload":
        if (
            adapter.get("release_version") != expected_release_version
            or adapter.get("release_manifest_sha256") != expected_release_manifest
            or expected_steward_commit
            or expected_adapter_tree
        ):
            raise SystemExit("publication attestation does not bind the current Steward release")
    else:
        raise SystemExit("publication adapter authority is invalid")
    archive_digest, archive_info = hash_file(archive_fd, archive_entry, maximum)
    digest = re.compile(r"sha256:[a-f0-9]{64}")
    if (
        archive_record.get("size_bytes") != archive_info.st_size
        or archive_record.get("sha256") != archive_digest
        or any(digest.fullmatch(str(image.get(name, ""))) is None for name in ("manifest_digest", "config_digest", "runtime_image_id"))
        or image.get("runtime_image_id") not in {image.get("manifest_digest"), image.get("config_digest")}
        or image.get("platform") != "linux/amd64"
    ):
        raise SystemExit("publication pair is not internally bound")
    return archive_digest, image["manifest_digest"], image["config_digest"], image["platform"], metadata_info


def open_staging():
    descriptor = os.open(staging.name, parent_flags, dir_fd=parent_fd)
    info = os.fstat(descriptor)
    if info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        raise SystemExit("publication staging directory is unsafe")
    entries = set(os.listdir(descriptor))
    if not entries <= {"archive.tar", "attestation.json"}:
        os.close(descriptor)
        raise SystemExit("publication staging directory contains an unknown entry")
    return descriptor, entries


def remove_staging(descriptor, entries):
    for name in sorted(entries):
        os.unlink(name, dir_fd=descriptor)
    os.close(descriptor)
    os.rmdir(staging.name, dir_fd=parent_fd)
    os.fsync(parent_fd)


try:
    if operation == "prepare":
        archive_info = named_stat(parent_fd, archive.name)
        metadata_info = named_stat(parent_fd, metadata.name)
        try:
            staging_fd, entries = open_staging()
        except FileNotFoundError:
            if archive_info is None and metadata_info is None:
                print("new")
                raise SystemExit(0)
            if archive_info is None or metadata_info is None:
                raise SystemExit("output archive or attestation already exists")
            require_file(archive_info, 1)
            require_file(metadata_info, 1)
            archive_digest, manifest, config, platform, _ = validate_pair(parent_fd, parent_fd)
            print("recovered")
            print(archive_digest)
            print(manifest)
            print(config)
            print(platform)
            raise SystemExit(0)

        staged_archive = named_stat(staging_fd, "archive.tar")
        staged_metadata = named_stat(staging_fd, "attestation.json")
        if archive_info is None and metadata_info is None:
            for info in (staged_archive, staged_metadata):
                if info is not None:
                    require_file(info, 1)
            remove_staging(staging_fd, entries)
            print("new")
        elif archive_info is None and metadata_info is not None:
            require_file(metadata_info, 2)
            require_file(staged_metadata, 2)
            require_file(staged_archive, 1)
            if identity(metadata_info) != identity(staged_metadata):
                raise SystemExit("orphan attestation does not belong to the staged publication")
            os.unlink(metadata.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            remove_staging(staging_fd, entries)
            print("new")
        elif archive_info is not None and metadata_info is None:
            raise SystemExit("archive exists without its attestation")
        else:
            for public, staged, staged_name in (
                (archive_info, staged_archive, "archive.tar"),
                (metadata_info, staged_metadata, "attestation.json"),
            ):
                expected_links = 2 if staged is not None else 1
                require_file(public, expected_links)
                if staged is not None:
                    require_file(staged, 2)
                    if identity(public) != identity(staged):
                        raise SystemExit("public file does not belong to the staged publication")
            archive_digest, manifest, config, platform, _ = validate_pair(parent_fd, parent_fd)
            remove_staging(staging_fd, entries)
            print("recovered")
            print(archive_digest)
            print(manifest)
            print(config)
            print(platform)
    elif operation == "commit":
        staging_fd, entries = open_staging()
        if entries != {"archive.tar", "attestation.json"}:
            raise SystemExit("publication staging directory is incomplete")
        staged_archive = named_stat(staging_fd, "archive.tar")
        staged_metadata = named_stat(staging_fd, "attestation.json")
        require_file(staged_archive, 1)
        require_file(staged_metadata, 1)
        if named_stat(parent_fd, archive.name) is not None or named_stat(parent_fd, metadata.name) is not None:
            raise SystemExit("refusing to overwrite an output archive or attestation")
        validate_pair(staging_fd, staging_fd, "archive.tar", "attestation.json")
        metadata_linked = False
        archive_linked = False
        try:
            os.link("attestation.json", metadata.name, src_dir_fd=staging_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            metadata_linked = True
            os.fsync(parent_fd)
            os.link("archive.tar", archive.name, src_dir_fd=staging_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            archive_linked = True
            os.fsync(parent_fd)
            remove_staging(staging_fd, entries)
        except BaseException:
            if not archive_linked and metadata_linked:
                try:
                    public = named_stat(parent_fd, metadata.name)
                    staged = named_stat(staging_fd, "attestation.json")
                    if public is not None and staged is not None and identity(public) == identity(staged):
                        os.unlink(metadata.name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                except OSError:
                    pass
            raise
    else:
        raise SystemExit("unknown publication operation")
finally:
    os.close(parent_fd)
PY
}
# END HERMES_PUBLICATION_PAIR

source_dir=
output=
non_interactive=false
keep_image=false
build_timeout=$default_build_timeout
clone_timeout=$default_clone_timeout
save_timeout=$default_save_timeout
min_free_bytes=$default_min_free_bytes
max_archive_bytes=$default_max_archive_bytes

while (( $# > 0 )); do
	case $1 in
	--output)
		(( $# >= 2 )) || usage_error "--output requires a value"
		output=$2
		shift 2
		;;
	--output=*) output=${1#*=}; shift ;;
	--source-dir)
		(( $# >= 2 )) || usage_error "--source-dir requires a value"
		source_dir=$2
		shift 2
		;;
	--source-dir=*) source_dir=${1#*=}; shift ;;
	--non-interactive) non_interactive=true; shift ;;
	--keep-image) keep_image=true; shift ;;
	--build-timeout)
		(( $# >= 2 )) || usage_error "--build-timeout requires a value"
		build_timeout=$2
		shift 2
		;;
	--build-timeout=*) build_timeout=${1#*=}; shift ;;
	--clone-timeout)
		(( $# >= 2 )) || usage_error "--clone-timeout requires a value"
		clone_timeout=$2
		shift 2
		;;
	--clone-timeout=*) clone_timeout=${1#*=}; shift ;;
	--save-timeout)
		(( $# >= 2 )) || usage_error "--save-timeout requires a value"
		save_timeout=$2
		shift 2
		;;
	--save-timeout=*) save_timeout=${1#*=}; shift ;;
	--min-free-bytes)
		(( $# >= 2 )) || usage_error "--min-free-bytes requires a value"
		min_free_bytes=$2
		shift 2
		;;
	--min-free-bytes=*) min_free_bytes=${1#*=}; shift ;;
	--max-archive-bytes)
		(( $# >= 2 )) || usage_error "--max-archive-bytes requires a value"
		max_archive_bytes=$2
		shift 2
		;;
	--max-archive-bytes=*) max_archive_bytes=${1#*=}; shift ;;
	-h|--help) usage; exit 0 ;;
	--) shift; (( $# == 0 )) || usage_error "positional arguments are not accepted" ;;
	-*) usage_error "unknown option: $1" ;;
	*) usage_error "positional arguments are not accepted: $1" ;;
	esac
done

validate_integer_range --build-timeout "$build_timeout" 300 14400
validate_integer_range --clone-timeout "$clone_timeout" 30 3600
validate_integer_range --save-timeout "$save_timeout" 30 3600
validate_integer_range --min-free-bytes "$min_free_bytes" $((1024 * 1024 * 1024)) $((1024 * 1024 * 1024 * 1024))
validate_integer_range --max-archive-bytes "$max_archive_bytes" $((1024 * 1024 * 1024)) $((64 * 1024 * 1024 * 1024))

if ! $non_interactive && [[ ! -t 0 || ! -t 1 ]]; then
	usage_error "no interactive terminal; pass --non-interactive"
fi
if [[ -z $output ]]; then
	$non_interactive && usage_error "--output is required with --non-interactive"
	default_output=$PWD/hermes-agent-adapter-${expected_revision:0:12}.tar
	read -r -p "Output archive [$default_output]: " output
	output=${output:-$default_output}
fi
[[ $output != *$'\n'* && $output != *$'\r'* ]] || usage_error "output path must not contain a newline"
[[ $(basename -- "$output") != .tar && $output == *.tar ]] || usage_error "output must be a named .tar archive"

for command in docker git python3 sha256sum tar timeout df awk od; do
	require_command "$command"
done

script_path=$(python3 -I - "${BASH_SOURCE[0]}" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
)
payload_root=$(cd "$(dirname "$script_path")/.." && pwd -P)
source_checkout_root=$(safe_git "$payload_root" rev-parse --show-toplevel 2>/dev/null || true)
if [[ -n $source_checkout_root ]]; then
	source_checkout_root=$(cd "$source_checkout_root" && pwd -P)
fi
adapter_source=
build_commit=
adapter_tree=
release_version=
release_manifest_sha256=
if [[ $source_checkout_root == "$payload_root" && -f $payload_root/adapters/hermes-agent/adapter.json ]]; then
	adapter_source=git-checkout
	root=$payload_root
	adapter_path=$root/adapters/hermes-agent
	safe_git "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Steward source root is not a Git checkout"
	build_commit=$(safe_git "$root" rev-parse HEAD)
	safe_git "$root" ls-files --error-unmatch scripts/build-hermes-adapter.sh >/dev/null 2>&1 \
		|| die "builder must be checked in before it can produce an attestation"
	committed_builder_blob=$(safe_git "$root" rev-parse "$build_commit:scripts/build-hermes-adapter.sh")
	current_builder_blob=$(safe_git "$root" hash-object --no-filters "$script_path")
	[[ $current_builder_blob == "$committed_builder_blob" ]] || die "builder differs from the committed Steward source"
	adapter_tree=$(safe_git "$root" rev-parse "$build_commit:adapters/hermes-agent")
elif [[ -f $payload_root/release.json && -f $payload_root/adapters/hermes-agent/adapter.json ]]; then
	adapter_source=release-payload
	root=$payload_root
	adapter_path=$payload_root/adapters/hermes-agent
	release_manifest=$payload_root/release.json
elif [[ -f $(dirname "$payload_root")/release.json && -f $payload_root/adapters/hermes-agent/adapter.json ]]; then
	adapter_source=release-payload
	root=$(dirname "$payload_root")
	adapter_path=$payload_root/adapters/hermes-agent
	release_manifest=$root/release.json
else
	die "Hermes adapter is absent from the Steward source or release payload"
fi
if [[ $adapter_source == release-payload ]]; then
	[[ -f $release_manifest && ! -L $release_manifest ]] || die "packaged builder requires an immutable release.json"
	release_version=$(python3 -I - "$adapter_path" "$script_path" "$release_manifest" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

adapter, script, manifest_path = map(pathlib.Path, sys.argv[1:])
if manifest_path.stat().st_size > 1 << 20:
    raise SystemExit("packaged release manifest is oversized")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
version = manifest.get("version") if isinstance(manifest, dict) else None
files = manifest.get("files") if isinstance(manifest, dict) else None
if (
    not isinstance(manifest, dict)
    or manifest.get("schema") != "steward.release.v2"
    or manifest.get("os") != "linux"
    or not isinstance(version, str)
    or re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version) is None
    or not isinstance(files, dict)
):
    raise SystemExit("packaged release manifest is invalid")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

actual = set()
for path in sorted(adapter.rglob("*")):
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode):
        continue
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"packaged adapter contains an unsafe entry: {path.relative_to(adapter)}")
    actual.add("integration/adapters/hermes-agent/" + path.relative_to(adapter).as_posix())
expected = {name for name in files if name.startswith("integration/adapters/hermes-agent/")}
if actual != expected:
    raise SystemExit("packaged adapter inventory differs from release.json")
builder_name = "integration/scripts/build-hermes-adapter.sh"
for name, path in [(name, adapter / name.removeprefix("integration/adapters/hermes-agent/")) for name in actual]:
    expected_digest = files.get(name)
    if not isinstance(expected_digest, str) or digest(path) != expected_digest:
        raise SystemExit(f"packaged release digest mismatch: {name}")
if not isinstance(files.get(builder_name), str) or digest(script) != files[builder_name]:
    raise SystemExit(f"packaged release digest mismatch: {builder_name}")
print(version)
PY
)
	release_manifest_sha256=$(sha256_file "$release_manifest")
fi
[[ -f $adapter_path/adapter.json && -f $adapter_path/Dockerfile ]] || die "Hermes adapter payload is incomplete"

output=$(python3 -I - "$output" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
)
output_parent=$(dirname -- "$output")
mkdir -p -- "$output_parent"
[[ -d $output_parent && ! -L $output_parent ]] || die "output parent must be a real directory"
attestation=$output.attestation.json
publish_dir=$output_parent/.$(basename -- "$output").steward-publish
publication_builder_sha256=$(sha256_file "$script_path")
publication_result=$(hermes_publication_pair prepare "$output" "$attestation" "$publish_dir" "$max_archive_bytes" \
	"$expected_repository" "$expected_revision" "$adapter_source" "$build_commit" "$adapter_tree" \
	"$release_version" "$release_manifest_sha256" "$publication_builder_sha256") \
	|| die "existing publication cannot be recovered safely"
mapfile -t publication_values <<<"$publication_result"
case ${publication_values[0]:-} in
new) ;;
recovered)
	(( ${#publication_values[@]} == 5 )) || die "recovered publication metadata is incomplete"
	progress "Recovered a completed Hermes adapter publication"
	echo "Archive:     $output"
	echo "Attestation: $attestation"
	echo "Image:       ${publication_values[2]} (${publication_values[4]})"
	echo "Config:      ${publication_values[3]}"
	echo "Archive SHA: ${publication_values[1]}"
	exit 0
	;;
*) die "publication recovery returned an invalid result" ;;
esac

docker info >/dev/null 2>&1 || die "Docker Engine is unavailable"
docker info --format '{{json .Runtimes}}' | python3 -I -c 'import json,sys; raise SystemExit(0 if "runsc" in json.load(sys.stdin) else 1)' \
	|| die "Docker runtime runsc is not registered"
docker_platform=$(docker info --format '{{.OSType}}/{{.Architecture}}')
[[ $docker_platform == linux/amd64 || $docker_platform == linux/x86_64 ]] \
	|| die "Hermes adapter builds are qualified only on linux/amd64; Docker reports $docker_platform"

tmp_base=${TMPDIR:-/tmp}
[[ -d $tmp_base ]] || die "temporary directory root does not exist: $tmp_base"
[[ $tmp_base != *:* && $tmp_base != *,* ]] || die "temporary directory root must not contain ':' or ','"
check_free_space "$tmp_base" "temporary filesystem"
check_free_space "$output_parent" "output filesystem"

work=$(mktemp -d "$tmp_base/steward-hermes-build.XXXXXX")
if ! mkdir -m 0700 -- "$publish_dir"; then
	rm -rf -- "$work"
	die "could not reserve publication staging directory"
fi
image_tag=steward-hermes-adapter-build:${expected_revision:0:12}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
image_owned=false
sandbox_name=

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	if $image_owned && { (( status != 0 )) || ! $keep_image; }; then
		docker image rm "$image_tag" >/dev/null 2>&1 || true
	fi
	[[ -z $sandbox_name ]] || docker rm -f "$sandbox_name" >/dev/null 2>&1 || true
	rm -rf -- "$work"
	if [[ ! -e $output && ! -L $output && ! -e $attestation && ! -L $attestation ]]; then
		rm -rf -- "$publish_dir"
	elif [[ -d $publish_dir && ! -L $publish_dir ]]; then
		echo "build-hermes-adapter: retained publication state for automatic recovery: $publish_dir" >&2
	fi
	exit "$status"
}
on_signal() {
	exit 130
}
trap cleanup EXIT
trap on_signal INT TERM

if [[ -z $source_dir ]]; then
	progress "Fetching pinned Hermes source $expected_revision"
	source_dir=$work/source
	git init -q "$source_dir"
	safe_git "$source_dir" remote add origin "$expected_repository"
	safe_git_timeout "$clone_timeout" "$source_dir" fetch --depth=1 --no-tags origin "$expected_revision"
	safe_git "$source_dir" checkout -q --detach FETCH_HEAD
else
	[[ -d $source_dir ]] || die "source directory does not exist: $source_dir"
	source_dir=$(cd "$source_dir" && pwd -P)
fi

actual_revision=$(safe_git "$source_dir" rev-parse HEAD 2>/dev/null || true)
[[ $actual_revision == "$expected_revision" ]] || die "source revision mismatch: expected $expected_revision"
source_tree=$(safe_git "$source_dir" rev-parse "$expected_revision^{tree}")

mkdir -p "$work/context/upstream" "$work/context/adapter"
safe_git "$source_dir" archive --format=tar --output="$work/source.tar" "$expected_revision"
if [[ $adapter_source == git-checkout ]]; then
	safe_git "$root" archive --format=tar --output="$work/adapter.tar" "$build_commit:adapters/hermes-agent"
else
	tar -cf "$work/adapter.tar" -C "$adapter_path" .
fi
source_archive_sha256=$(sha256_file "$work/source.tar")
tar -xf "$work/source.tar" -C "$work/context/upstream"
tar -xf "$work/adapter.tar" -C "$work/context/adapter"
adapter_file_set_sha256=$(canonical_file_set_digest "$work/context/adapter")

mapfile -t adapter_values < <(python3 -I - "$work/context/adapter/adapter.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
bases = document.get("base_images")
if not isinstance(bases, list) or len(bases) != 1 or not isinstance(bases[0], dict):
    raise SystemExit("adapter must define exactly one base image")
print(document.get("upstream", {}).get("repository", ""))
print(document.get("upstream", {}).get("revision", ""))
print(bases[0].get("reference", ""))
PY
)
(( ${#adapter_values[@]} == 3 )) || die "adapter metadata is invalid"
[[ ${adapter_values[0]} == "$expected_repository" ]] || die "adapter repository pin drift"
[[ ${adapter_values[1]} == "$expected_revision" ]] || die "adapter revision pin drift"
base_image_reference=${adapter_values[2]}
[[ $base_image_reference =~ @sha256:[a-f0-9]{64}$ ]] || die "adapter base image is not digest-pinned"
dockerfile_base=$(awk -F= '/^ARG UV_IMAGE=/{print substr($0, index($0, "=") + 1); exit}' "$work/context/adapter/Dockerfile")
[[ $dockerfile_base == "$base_image_reference" ]] || die "Dockerfile base image differs from adapter metadata"

(cd "$work/context/upstream" && sha256sum -c "$work/context/adapter/source-inputs.sha256") >/dev/null \
	|| die "pinned Hermes source inputs failed verification"
build_recipe_sha256=$(sha256_file "$work/context/adapter/Dockerfile")
source_inputs_sha256=$(sha256_file "$work/context/adapter/source-inputs.sha256")
builder_sha256=$publication_builder_sha256

if ! $non_interactive; then
	echo >&2
	echo "Pinned source: $expected_revision" >&2
	echo "Source mode:   $([[ $source_dir == "$work/source" ]] && echo online-temporary || echo offline-checkout)" >&2
	echo "Output:        $output" >&2
	echo "Base image:    $base_image_reference" >&2
	read -r -p "Build and publish this archive? [y/N] " answer
	[[ $answer == y || $answer == Y || $answer == yes || $answer == YES ]] || die "cancelled"
fi

# The sandbox runs as the fixed non-root runtime UID. Expose only traversal to
# the private temporary parent and read-only access to the explicit bind roots;
# all other build state remains owner-only.
chmod 0711 "$work" "$work/context"
chmod 0555 "$work/context/upstream" "$work/context/adapter"

progress "Planning exact Linux wheel fetches from the verified Hermes lockfile"
wheel_plan=$work/wheel-plan.json
docker run --rm --runtime runsc --network=none --read-only --cap-drop ALL \
	--security-opt no-new-privileges:true --pids-limit 32 \
	--memory 268435456 --memory-swap 268435456 --cpus 1 \
	--user 65532:65532 --workdir /input/upstream --log-driver none \
	--mount "type=bind,source=$work/context/upstream,target=/input/upstream,readonly" \
	--entrypoint python3 "$base_image_reference" -I -c '
import json
import pathlib
import re
import sys
import tomllib

lock = tomllib.loads(pathlib.Path("uv.lock").read_text(encoding="utf-8"))
if lock.get("version") != 1 or not isinstance(lock.get("package"), list):
    raise SystemExit("unsupported Hermes uv.lock schema")

def compatible(filename):
    if not filename.endswith(".whl") or len(filename) > 256:
        return False
    try:
        python_tag, abi_tag, platform_tag = filename[:-4].rsplit("-", 3)[-3:]
    except ValueError:
        return False
    python_tags = python_tag.split(".")
    abi_tags = abi_tag.split(".")
    platform_tags = platform_tag.split(".")
    python_ok = any(
        tag in {"py3", "py313", "cp313"}
        or (
            tag.startswith("cp")
            and tag[2:].isdigit()
            and int(tag[2:]) <= 313
            and "abi3" in abi_tags
        )
        for tag in python_tags
    )
    abi_ok = any(tag in {"none", "cp313", "abi3"} for tag in abi_tags)
    platform_ok = any(
        tag == "any"
        or tag == "linux_x86_64"
        or (tag.startswith("manylinux") and tag.endswith("_x86_64"))
        for tag in platform_tags
    )
    return python_ok and abi_ok and platform_ok

artifacts = {}
for package in lock["package"]:
    if not isinstance(package, dict):
        raise SystemExit("uv.lock contains an invalid package entry")
    source = package.get("source")
    if source == {"editable": "."}:
        continue
    if source != {"registry": "https://pypi.org/simple"}:
        raise SystemExit("uv.lock contains a non-PyPI package source")
    for wheel in package.get("wheels", []):
        if not isinstance(wheel, dict):
            raise SystemExit("uv.lock contains an invalid wheel entry")
        url = wheel.get("url")
        digest = wheel.get("hash")
        size = wheel.get("size")
        if not isinstance(url, str):
            raise SystemExit("uv.lock wheel URL is invalid")
        filename = url.rsplit("/", 1)[-1]
        if not compatible(filename):
            continue
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,251}\.whl", filename) is None
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise SystemExit("uv.lock contains an invalid compatible wheel")
        descriptor = {"filename": filename, "sha256": digest[7:], "size": size, "url": url}
        prior = artifacts.get(filename)
        if prior is not None and prior != descriptor:
            raise SystemExit("uv.lock maps one wheel filename to different artifacts")
        artifacts[filename] = descriptor

encoded = json.dumps(
    {"artifacts": [artifacts[name] for name in sorted(artifacts)], "schema": "steward.hermes-wheel-plan.v1"},
    ensure_ascii=True,
    separators=(",", ":"),
    sort_keys=True,
).encode() + b"\n"
if len(encoded) > 1 << 20:
    raise SystemExit("Hermes wheel plan is oversized")
sys.stdout.buffer.write(encoded)
' | python3 -I -c '
import os
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
content = sys.stdin.buffer.read((1 << 20) + 1)
if not content or len(content) > 1 << 20:
    raise SystemExit("Hermes wheel plan is empty or oversized")
with destination.open("xb") as stream:
    stream.write(content)
    stream.flush()
    os.fsync(stream.fileno())
' "$wheel_plan"

progress "Fetching exact locked wheels without executing package code"
mkdir "$work/wheelhouse"
timeout "$build_timeout" python3 -I - "$wheel_plan" "$work/wheelhouse" "$wheelhouse_max_files" \
	"$wheelhouse_max_file_bytes" "$wheelhouse_max_bytes" <<'PY'
import hashlib
import http.client
import json
import os
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

plan_path = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
max_files, max_file_bytes, max_total_bytes = map(int, sys.argv[3:])
plan = json.loads(plan_path.read_text(encoding="utf-8"))
artifacts = plan.get("artifacts") if isinstance(plan, dict) else None
if not isinstance(plan, dict) or plan.get("schema") != "steward.hermes-wheel-plan.v1" or not isinstance(artifacts, list):
    raise SystemExit("Hermes wheel plan is invalid")
if not artifacts or len(artifacts) > max_files:
    raise SystemExit("Hermes wheel plan has an invalid artifact count")

class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise urllib.error.HTTPError(request.full_url, code, "redirect refused", headers, file_pointer)

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    RejectRedirects(),
)
seen = set()
declared_total = 0
for artifact in artifacts:
    if not isinstance(artifact, dict) or set(artifact) != {"filename", "sha256", "size", "url"}:
        raise SystemExit("Hermes wheel plan contains an invalid descriptor")
    filename = artifact["filename"]
    digest = artifact["sha256"]
    size = artifact["size"]
    url = artifact["url"]
    parsed = urllib.parse.urlsplit(url)
    if (
        not isinstance(filename, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,251}\.whl", filename) is None
        or filename in seen
        or not isinstance(digest, str)
        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > max_file_bytes
        or parsed.scheme != "https"
        or parsed.hostname != "files.pythonhosted.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1]) != filename
        or not parsed.path.startswith("/packages/")
    ):
        raise SystemExit("Hermes wheel plan exceeds its fetch authority")
    seen.add(filename)
    declared_total += size
    if declared_total > max_total_bytes:
        raise SystemExit("Hermes wheel plan exceeds its total byte limit")

    target = destination / filename
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "User-Agent": "steward-hermes-wheel-fetch/1"})
    written = 0
    calculated = hashlib.sha256()
    try:
        with opener.open(request, timeout=60) as response, target.open("xb") as stream:
            if response.status != http.client.OK or response.geturl() != url:
                raise RuntimeError("unexpected wheel response")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and (not content_length.isdigit() or int(content_length) != size):
                raise RuntimeError("wheel response size differs from lockfile")
            while True:
                chunk = response.read(min(1024 * 1024, size - written + 1))
                if not chunk:
                    break
                written += len(chunk)
                if written > size:
                    raise RuntimeError("wheel response exceeds lockfile size")
                calculated.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if written != size or calculated.hexdigest() != digest:
            raise RuntimeError("wheel response does not match lockfile")
        target.chmod(0o444)
    except Exception:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise

directory_fd = os.open(destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
chmod 0555 "$work/wheelhouse"

progress "Building Hermes dependencies without network inside bounded gVisor sandbox (timeout ${build_timeout}s)"
sandbox_name=steward-hermes-build-sandbox-${expected_revision:0:12}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
# shellcheck disable=SC2016 # Expanded by the sandbox shell, not this builder.
sandbox_command='set -eu
mkdir -p /tmp/build /tmp/home
cp -R /input/upstream/. /tmp/build/
chmod -R u+rwX /tmp/build
cd /tmp/build
sha256sum -c /input/adapter/source-inputs.sha256 >&2
uv export --frozen --offline --no-dev --extra mcp --extra homeassistant \
    --no-emit-project --format requirements-txt --output-file /tmp/requirements.txt >/dev/null
uv venv --offline --python /usr/local/bin/python3 .venv >&2
uv pip sync --offline --no-index --find-links /input/wheelhouse \
    --no-build --require-hashes --python .venv/bin/python /tmp/requirements.txt >&2
uv pip install --offline --no-index --find-links /input/wheelhouse \
    --no-build --python .venv/bin/python "setuptools==81.0.0" >&2
uv pip install --offline --no-index --find-links /input/wheelhouse \
    --no-deps --no-build-isolation --python .venv/bin/python . >&2
for script in .venv/bin/*; do
    if [ -f "$script" ] && IFS= read -r first_line <"$script"; then
        case "$first_line" in
            \#\!/tmp/build/.venv/bin/python*)
                sed -i "1s|^#!/tmp/build/.venv/bin/python|#!/opt/hermes/.venv/bin/python|" "$script"
                ;;
        esac
    fi
done
if grep -RIl "^#!/tmp/build/.venv/bin/python" .venv/bin >/dev/null; then
    exit 1
fi
tar -cf - .venv
'
docker create --name "$sandbox_name" \
	--runtime runsc --network=none --read-only --cap-drop ALL \
	--security-opt no-new-privileges:true --pids-limit "$sandbox_pids" \
	--memory "$sandbox_memory_bytes" --memory-swap "$sandbox_memory_bytes" --cpus "$sandbox_cpus" \
	--tmpfs "/tmp:rw,nosuid,nodev,size=$sandbox_memory_bytes" \
	--user 65532:65532 --workdir /tmp \
	--env HOME=/tmp/home --env UV_CACHE_DIR=/tmp/uv-cache --env UV_LINK_MODE=copy \
	--log-driver none \
	--mount "type=bind,source=$work/context/upstream,target=/input/upstream,readonly" \
	--mount "type=bind,source=$work/context/adapter,target=/input/adapter,readonly" \
	--mount "type=bind,source=$work/wheelhouse,target=/input/wheelhouse,readonly" \
	--entrypoint /bin/sh "$base_image_reference" -ceu "$sandbox_command" >/dev/null
stream_status=0
timeout "$build_timeout" docker start -a "$sandbox_name" | python3 -I -c '
import os
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
written = 0
with destination.open("xb") as stream:
    while True:
        chunk = sys.stdin.buffer.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise SystemExit("gVisor build artifact exceeds configured size limit")
        stream.write(chunk)
    stream.flush()
    os.fsync(stream.fileno())
if written == 0:
    raise SystemExit("gVisor build sandbox produced an empty artifact")
' "$work/venv.tar" "$sandbox_output_bytes" || stream_status=$?
sandbox_status=$(docker inspect --format '{{.State.ExitCode}}' "$sandbox_name" 2>/dev/null || true)
[[ $stream_status == 0 && $sandbox_status == 0 ]] || \
	die "gVisor build sandbox or bounded artifact stream failed (stream=$stream_status, sandbox=${sandbox_status:-unknown})"
venv_archive_size=$(python3 -I - "$work/venv.tar" <<'PY'
import os
import stat
import sys

info = os.lstat(sys.argv[1])
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    raise SystemExit("gVisor build artifact is not a single-link regular file")
print(info.st_size)
PY
)
(( venv_archive_size > 0 && venv_archive_size <= sandbox_output_bytes )) || die "gVisor build artifact is empty or oversized"

mkdir -p "$work/final-context/adapter" "$work/final-context/upstream" "$work/final-context/artifact/venv"
cp -a "$work/context/adapter"/. "$work/final-context/adapter/"
install -m 0444 "$work/context/upstream/LICENSE" "$work/final-context/upstream/LICENSE"
python3 -I - "$work/venv.tar" "$sandbox_output_bytes" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    if not members or len(members) > 100000:
        raise SystemExit("gVisor build artifact has an invalid member count")
    normalized = {}
    symlinks = set()
    total = 0
    for member in members:
        raw = member.name.removeprefix("./")
        path = pathlib.PurePosixPath(raw)
        if not raw or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise SystemExit("gVisor build artifact contains an unsafe path")
        if path.parts[0] != ".venv" or path in normalized:
            raise SystemExit("gVisor build artifact escaped or duplicated its root")
        if not (member.isdir() or member.isfile() or member.issym()) or member.mode & 0o7000:
            raise SystemExit("gVisor build artifact contains an unsafe member type or mode")
        if member.isfile():
            if member.size < 0 or member.size > limit:
                raise SystemExit("gVisor build artifact member is oversized")
            total += member.size
            if total > limit:
                raise SystemExit("gVisor build artifact expands beyond its limit")
        if member.issym():
            if not member.linkname or len(member.linkname.encode("utf-8")) > 4096 or "\x00" in member.linkname:
                raise SystemExit("gVisor build artifact contains an unsafe symlink")
            symlinks.add(path)
        normalized[path] = member
    for path in normalized:
        if any(pathlib.PurePosixPath(*path.parts[:index]) in symlinks for index in range(1, len(path.parts))):
            raise SystemExit("gVisor build artifact places content below a symlink")
PY
tar --no-same-owner -xf "$work/venv.tar" -C "$work/final-context/artifact/venv"
mkdir -p "$work/final-context/artifact/state/home"
chmod 0700 "$work/final-context/artifact/state" "$work/final-context/artifact/state/home"
printf 'docker\n' >"$work/final-context/artifact/install_method"
chmod 0444 "$work/final-context/artifact/install_method"

docker image inspect "$image_tag" >/dev/null 2>&1 && die "temporary image tag already exists"
progress "Assembling pinned Hermes adapter without upstream build hooks (timeout ${build_timeout}s)"
image_owned=true
timeout "$build_timeout" docker build --network=none --pull=false --provenance=false \
	--build-arg "HERMES_SOURCE_REVISION=$expected_revision" \
	-f "$work/final-context/adapter/Dockerfile" -t "$image_tag" "$work/final-context"

runtime_image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
image_user=$(docker image inspect --format '{{.Config.User}}' "$image_tag")
image_volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$image_tag")
image_os=$(docker image inspect --format '{{.Os}}' "$image_tag")
image_arch=$(docker image inspect --format '{{.Architecture}}' "$image_tag")
image_source_revision=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.hermes.source-revision"}}' "$image_tag")
[[ $runtime_image_id =~ ^sha256:[a-f0-9]{64}$ ]] || die "built image has an invalid runtime identity digest"
[[ $image_user == 65532:65532 ]] || die "built image user is $image_user, not 65532:65532"
[[ $image_volumes == null || $image_volumes == '{}' ]] || die "built image declares a volume"
[[ -n $image_os && -n $image_arch ]] || die "built image platform is incomplete"
[[ $image_source_revision == "$expected_revision" ]] || die "built image source revision label is invalid"
image_platform=$image_os/$image_arch

check_free_space "$output_parent" "output filesystem"
archive_tmp=$publish_dir/archive.tar
progress "Saving bounded image archive (timeout ${save_timeout}s)"
timeout "$save_timeout" docker save "$image_tag" | python3 -I -c '
import os
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
written = 0
with destination.open("xb") as stream:
    while True:
        chunk = sys.stdin.buffer.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise SystemExit("Docker archive exceeds configured size limit")
        stream.write(chunk)
    stream.flush()
    os.fsync(stream.fileno())
if written == 0:
    raise SystemExit("Docker produced an empty archive")
' "$archive_tmp" "$max_archive_bytes"

mapfile -t archive_image_values < <(python3 -I - "$archive_tmp" "$image_tag" "$runtime_image_id" "$image_os" "$image_arch" <<'PY'
import hashlib
import json
import re
import sys
import tarfile

archive_path, expected_tag, runtime_id, expected_os, expected_arch = sys.argv[1:]
digest = re.compile(r"sha256:[a-f0-9]{64}")
blob = re.compile(r"blobs/sha256/([a-f0-9]{64})")

with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    if len(members) > 512 or len({member.name for member in members}) != len(members):
        raise SystemExit("Docker archive has an invalid member inventory")
    if any(not (member.isfile() or member.isdir()) for member in members):
        raise SystemExit("Docker archive contains a non-file member")
    by_name = {member.name: member for member in members}

    def read(name, maximum):
        member = by_name.get(name)
        if member is None or not member.isfile() or member.size < 0 or member.size > maximum:
            raise SystemExit(f"Docker archive member is missing or oversized: {name}")
        stream = archive.extractfile(member)
        if stream is None:
            raise SystemExit(f"Docker archive member cannot be read: {name}")
        content = stream.read(maximum + 1)
        if len(content) != member.size or len(content) > maximum:
            raise SystemExit(f"Docker archive member changed size: {name}")
        return content

    legacy = json.loads(read("manifest.json", 1 << 20))
    if not isinstance(legacy, list) or len(legacy) != 1 or not isinstance(legacy[0], dict):
        raise SystemExit("Docker archive must contain exactly one image")
    image = legacy[0]
    if image.get("RepoTags") != [expected_tag]:
        raise SystemExit("Docker archive tag differs from the temporary build tag")
    config_path = image.get("Config")
    match = blob.fullmatch(config_path) if isinstance(config_path, str) else None
    if match is None:
        raise SystemExit("Docker archive config path is invalid")
    config_bytes = read(config_path, 1 << 20)
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    if config_digest != "sha256:" + match.group(1):
        raise SystemExit("Docker archive config digest is invalid")
    config = json.loads(config_bytes)
    if (
        not isinstance(config, dict)
        or config.get("os") != expected_os
        or config.get("architecture") != expected_arch
        or not isinstance(config.get("config"), dict)
        or config["config"].get("User") != "65532:65532"
        or config["config"].get("Volumes") not in (None, {})
    ):
        raise SystemExit("Docker archive config contract is invalid")

    index = json.loads(read("index.json", 1 << 20))
    descriptors = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(descriptors, list) or len(descriptors) != 1 or not isinstance(descriptors[0], dict):
        raise SystemExit("Docker archive OCI index is invalid")
    manifest_digest = descriptors[0].get("digest")
    if not isinstance(manifest_digest, str) or digest.fullmatch(manifest_digest) is None:
        raise SystemExit("Docker archive manifest digest is invalid")
    manifest_path = "blobs/sha256/" + manifest_digest.removeprefix("sha256:")
    manifest_bytes = read(manifest_path, 1 << 20)
    if "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest:
        raise SystemExit("Docker archive manifest content does not match its digest")
    manifest = json.loads(manifest_bytes)
    descriptor = manifest.get("config") if isinstance(manifest, dict) else None
    if not isinstance(descriptor, dict) or descriptor.get("digest") != config_digest:
        raise SystemExit("Docker archive manifest does not bind the config digest")
    annotation = descriptors[0].get("annotations", {}).get("config.digest")
    if annotation is not None and annotation != config_digest:
        raise SystemExit("Docker archive index config annotation is inconsistent")
    if runtime_id not in {manifest_digest, config_digest}:
        raise SystemExit("Docker runtime image identity is not bound by the archive")

print(manifest_digest)
print(config_digest)
PY
)
(( ${#archive_image_values[@]} == 2 )) || die "Docker archive image identity is incomplete"
image_manifest_digest=${archive_image_values[0]}
image_config_digest=${archive_image_values[1]}

archive_sha256=$(sha256_file "$archive_tmp")
archive_size=$(file_size "$archive_tmp")
attestation_tmp=$publish_dir/attestation.json
python3 -I - "$attestation_tmp" "$(basename -- "$output")" "$expected_repository" "$expected_revision" "$source_tree" \
	"$source_archive_sha256" "$adapter_source" "$build_commit" "$adapter_tree" "$release_version" \
	"$release_manifest_sha256" "$adapter_file_set_sha256" "$build_recipe_sha256" \
	"$source_inputs_sha256" "$builder_sha256" "$base_image_reference" "$image_manifest_digest" \
	"$image_config_digest" "$runtime_image_id" "$image_platform" \
	"$archive_sha256" "$archive_size" <<'PY'
import json
import os
import pathlib
import sys

(
    destination, archive_name, repository, revision, source_tree, source_archive,
    adapter_source, steward_commit, adapter_tree, release_version, release_manifest,
    adapter_files, dockerfile, source_inputs, builder,
    base_image, manifest_digest, config_digest, runtime_image_id, platform, archive_digest, archive_size,
) = sys.argv[1:]
adapter = {
    "contract": "steward.hermes-agent.v1",
    "file_set_sha256": adapter_files,
    "source": adapter_source,
}
if adapter_source == "git-checkout":
    adapter["git_tree"] = adapter_tree
    adapter["steward_commit"] = steward_commit
elif adapter_source == "release-payload":
    adapter["release_manifest_sha256"] = release_manifest
    adapter["release_version"] = release_version
else:
    raise SystemExit("invalid adapter source")
payload = {
    "adapter": adapter,
    "archive": {
        "file": archive_name,
        "sha256": archive_digest,
        "size_bytes": int(archive_size),
    },
    "build_recipe": {
        "base_image": base_image,
        "build_isolation": "gvisor-runsc",
        "builder_sha256": builder,
        "dockerfile_sha256": dockerfile,
        "id": "steward.hermes-adapter.docker-build.v1",
        "network_scope": "verified-host-wheel-fetch;gvisor-hooks-network-none",
        "pull_newer_base": False,
        "runtime_executed": False,
        "source_inputs_sha256": source_inputs,
        "upstream_build_hooks_in_final_assembly": False,
    },
    "contains_agent_content": False,
    "image": {
        "config_digest": config_digest,
        "declared_volumes": False,
        "manifest_digest": manifest_digest,
        "platform": platform,
        "runtime_image_id": runtime_image_id,
        "user": "65532:65532",
    },
    "schema_version": "steward.hermes-adapter-build-attestation.v1",
    "source": {
        "archive_sha256": source_archive,
        "git_tree": source_tree,
        "repository": repository,
        "revision": revision,
    },
}
encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"
path = pathlib.Path(destination)
with path.open("xb") as stream:
    stream.write(encoded)
    stream.flush()
    os.fsync(stream.fileno())
PY

hermes_publication_pair commit "$output" "$attestation" "$publish_dir" "$max_archive_bytes" \
	"$expected_repository" "$expected_revision" "$adapter_source" "$build_commit" "$adapter_tree" \
	"$release_version" "$release_manifest_sha256" "$publication_builder_sha256"

progress "Hermes adapter archive created"
echo "Archive:     $output"
echo "Attestation: $attestation"
echo "Image:       $image_manifest_digest ($image_platform)"
echo "Config:      $image_config_digest"
echo "Archive SHA: $archive_sha256"
