#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
image='ghcr.io/openbao/openbao@sha256:436eaf9778cad75507ff70ea26ace30dcbe15606e619ac3823495663d7f7c115'
temp_root=${TMPDIR:-/tmp}
temp_root=${temp_root%/}
work=$(mktemp -d "$temp_root/steward-openbao-smoke.XXXXXX")
work=$(cd "$work" && pwd -P)
container="steward-openbao-smoke-$$"
host_uid=$(id -u)
host_gid=$(id -g)

cleanup() {
	if docker inspect "$container" >/dev/null 2>&1; then
		docker exec "$container" chown -R "$host_uid:$host_gid" /work >/dev/null 2>&1 || true
		docker rm -f "$container" >/dev/null 2>&1 || true
	fi
	rm -rf -- "$work"
}

server_diagnostics() {
	docker inspect "$container" --format \
		'openbao-materializer-smoke: container status={{.State.Status}} error={{.State.Error}} exit={{.State.ExitCode}}' >&2 || true
	docker logs "$container" 2>&1 |
		sed -E 's/^(Unseal Key|Root Token):.*/\1: [redacted]/' >&2 || true
}
trap cleanup EXIT INT TERM
cd "$repository"

for command in docker go install; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "openbao-materializer-smoke: $command is required" >&2
		exit 2
	}
done
docker info >/dev/null 2>&1

architecture=$(docker info --format '{{.Architecture}}' 2>/dev/null)
case "$architecture" in
	amd64 | x86_64) goarch=amd64 ;;
	arm64 | aarch64) goarch=arm64 ;;
	*)
		echo "openbao-materializer-smoke: unsupported Docker architecture $architecture" >&2
		exit 2
		;;
esac

install -d -m 0700 \
	"$work/tls" "$work/role" "$work/secretid" "$work/secrets" "$work/status"

go run ./cmd/stewardctl secret openbao compile \
	-plan "$repository/scripts/fixtures/openbao-materializer-plan-v1.json" \
	-out "$work/bundle" >/dev/null
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -o "$work/stewardctl" ./cmd/stewardctl
chmod 0755 "$work/stewardctl"

docker run -d --name "$container" --user 0 --cap-add=IPC_LOCK \
	-e BAO_SKIP_DROP_ROOT=1 -v "$work:/work" "$image" \
	server -dev -dev-tls -dev-tls-cert-dir=/work/tls \
	-dev-listen-address=127.0.0.1:8200 \
	-dev-root-token-id=steward-smoke-root -dev-no-store-token >/dev/null

bao=(docker exec -e BAO_ADDR=https://127.0.0.1:8200 \
	-e BAO_CACERT=/work/tls/vault-ca.pem -e BAO_TOKEN=steward-smoke-root \
	"$container" bao)
for _ in $(seq 1 30); do
	if "${bao[@]}" status -format=json >/dev/null 2>&1; then
		server_ready=true
		break
	fi
	if [[ $(docker inspect "$container" --format '{{.State.Running}}') != true ]]; then
		server_diagnostics
		exit 1
	fi
	sleep 1
done
if [[ ${server_ready:-false} != true ]]; then
	server_diagnostics
	exit 1
fi

docker exec "$container" chown -R 0:0 \
	/work/bundle /work/role /work/secretid /work/secrets /work/status /work/stewardctl
"${bao[@]}" auth enable approle >/dev/null
"${bao[@]}" secrets enable -path=steward-kv kv-v2 >/dev/null
"${bao[@]}" kv put -mount=steward-kv tenant-a/inference-primary \
	value=smoke-inference-key-123456 >/dev/null
"${bao[@]}" policy write steward-node /work/bundle/openbao-read-policy.hcl >/dev/null
"${bao[@]}" write auth/approle/role/steward-node \
	token_policies=steward-node token_ttl=5m token_max_ttl=10m \
	secret_id_num_uses=1 >/dev/null
docker exec -e BAO_ADDR=https://127.0.0.1:8200 \
	-e BAO_CACERT=/work/tls/vault-ca.pem -e BAO_TOKEN=steward-smoke-root \
	"$container" sh -c \
	'bao read -field=role_id auth/approle/role/steward-node/role-id > /work/role/role-id &&
	 bao write -f -field=secret_id auth/approle/role/steward-node/secret-id > /work/secretid/secret-id &&
	 chmod 0600 /work/role/role-id /work/secretid/secret-id'

docker exec "$container" /work/stewardctl secret materialization prepare \
	-manifest /work/bundle/materialization.json \
	-root /work/secrets -status-root /work/status >/dev/null
docker exec -d "$container" sh -c \
	'exec bao agent -config=/work/bundle/agent.hcl -log-format=json -log-level=info > /work/agent.log 2>&1'
for _ in $(seq 1 30); do
	if docker exec "$container" sh -c \
		'test -f /work/status/tenant-a/inference-primary.epoch &&
		 test "$(cat /work/status/tenant-a/inference-primary.epoch)" = 1' >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
docker exec "$container" /work/stewardctl secret materialization check \
	-manifest /work/bundle/materialization.json \
	-root /work/secrets -status-root /work/status >/dev/null
docker exec "$container" sh -c \
	'test ! -e /work/secretid/secret-id &&
	 test "$(cat /work/secrets/tenant-a/inference-primary)" = smoke-inference-key-123456'

go run ./cmd/stewardctl secret openbao compile \
	-plan "$repository/scripts/fixtures/openbao-materializer-plan-v2.json" \
	-out "$work/bundle2" >/dev/null
"${bao[@]}" kv put -mount=steward-kv -cas=1 tenant-a/inference-primary \
	value=rotated-inference-key-654321 >/dev/null
docker exec "$container" install -o 0 -g 0 -m 0640 \
	/work/bundle2/materialization.json /work/bundle/materialization.json
docker exec -e BAO_ADDR=https://127.0.0.1:8200 \
	-e BAO_CACERT=/work/tls/vault-ca.pem -e BAO_TOKEN=steward-smoke-root \
	"$container" sh -c \
	'bao write -f -field=secret_id auth/approle/role/steward-node/secret-id > /work/secretid/secret-id &&
	 chmod 0600 /work/secretid/secret-id'
docker exec -d "$container" sh -c \
	'exec bao agent -config=/work/bundle/agent.hcl -log-format=json -log-level=info > /work/agent-rotation.log 2>&1'
for _ in $(seq 1 30); do
	if docker exec "$container" sh -c \
		'test "$(cat /work/status/tenant-a/inference-primary.epoch 2>/dev/null)" = 2' >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
report=$(docker exec "$container" /work/stewardctl secret materialization check \
	-manifest /work/bundle/materialization.json \
	-root /work/secrets -status-root /work/status)
[[ $report == *'"ready":true'* && $report == *'"expected_epoch":2'* && $report == *'"observed_epoch":2'* ]]
docker exec "$container" sh -c \
	'test "$(cat /work/secrets/tenant-a/inference-primary)" = rotated-inference-key-654321'

echo 'openbao-materializer-smoke: TLS AppRole render, SecretID removal, and CAS rotation passed'
