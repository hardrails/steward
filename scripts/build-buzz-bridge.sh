#!/usr/bin/env bash
set -euo pipefail

fail() {
	printf 'build-buzz-bridge: %s\n' "$1" >&2
	exit 1
}

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source_dir=
output=
offline=false

while (($#)); do
	case $1 in
	--source-dir)
		(($# >= 2)) || fail '--source-dir requires a path'
		source_dir=$2
		shift 2
		;;
	--output)
		(($# >= 2)) || fail '--output requires a new directory path'
		output=$2
		shift 2
		;;
	--offline)
		offline=true
		shift
		;;
	*) fail "unknown argument: $1" ;;
	esac
done

[[ -n $output ]] || fail '--output is required'
[[ ! -e $output ]] || fail 'output path already exists'
output_parent=$(cd -- "$(dirname -- "$output")" && pwd -P) || fail 'output parent does not exist'
output=$output_parent/$(basename -- "$output")
for command in git python3 cargo go install; do
	command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

pin_field() {
	python3 -I - "$root/integrations/buzz/source-lock.json" "$1" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fields = {
    "release": document["selection"]["release"],
    "revision": document["revision"],
    "rust": document["toolchain"]["rust"],
}
print(fields[sys.argv[2]])
PY
}
release=$(pin_field release)
revision=$(pin_field revision)
rust=$(pin_field rust)

temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

if [[ -z $source_dir ]]; then
	$offline && fail '--offline requires --source-dir and a populated Cargo cache or vendor configuration'
	git -c init.defaultBranch=main init -q "$temporary/source"
	git -C "$temporary/source" remote add origin https://github.com/block/buzz.git
	git -C "$temporary/source" fetch -q --depth=1 origin "refs/tags/$release:refs/tags/$release"
	git -C "$temporary/source" checkout -q --detach "$release"
	source_dir=$temporary/source
else
	source_dir=$(cd -- "$source_dir" && pwd -P)
fi

python3 -I "$root/scripts/update-buzz-pin.py" \
	--source-dir "$source_dir" --release-tag "$release" --repository-root "$root" --check \
	|| fail 'source checkout does not match the committed Buzz lock'

git clone -q --no-hardlinks "$source_dir" "$temporary/build-source"
git -C "$temporary/build-source" checkout -q --detach "$revision"
git -C "$temporary/build-source" apply --check "$root/integrations/buzz/buzz-cli-verification.patch"
git -C "$temporary/build-source" apply "$root/integrations/buzz/buzz-cli-verification.patch"

[[ $(cd -- "$temporary/build-source" && rustc --version | awk '{print $2}') == "$rust" ]] \
	|| fail "rustc must be the source-locked version $rust"
cargo_arguments=(build --locked --release -p buzz-cli)
$offline && cargo_arguments+=(--offline)
(cd -- "$temporary/build-source" && cargo "${cargo_arguments[@]}")

mkdir -m 0700 -- "$output"
(cd -- "$root" && go build -trimpath -o "$output/steward-buzz-bridge" ./cmd/steward-buzz-bridge)
(cd -- "$root" && go build -trimpath -o "$output/stewardctl" ./cmd/stewardctl)
install -m 0555 "$temporary/build-source/target/release/buzz" "$output/buzz"
install -m 0444 "$root/integrations/buzz/source-lock.json" "$output/source-lock.json"
install -m 0444 "$root/integrations/buzz/buzz-cli-verification.patch" "$output/buzz-cli-verification.patch"
install -m 0444 "$source_dir/LICENSE" "$output/BUZZ-LICENSE"
install -m 0444 "$root/LICENSE" "$output/STEWARD-LICENSE"

printf 'Built the Steward Buzz bridge in %s\n' "$output"
