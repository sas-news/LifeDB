#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STAGE=${1:-all}
PYTHON_BIN="$ROOT/.venv/bin/python"
TMP_ROOT=$(mktemp -d /tmp/lifedb-ci.XXXXXX)
OWNER_TOKEN="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
IMAGE_TAG="lifedb:ci-${OWNER_TOKEN}"
IMAGE_ID=""
CONTAINER_PREFIX="lifedb-ci-${OWNER_TOKEN}"
CONTAINER_IDS=(); LAST_ID=""
CONTAINER_NAMES=()
DOCKER_CONFIG="$TMP_ROOT/docker-config"
HOME="$TMP_ROOT/home"; XDG_CONFIG_HOME="$TMP_ROOT/config"; HERMES_HOME="$TMP_ROOT/hermes"
BUILD_ROOT="$TMP_ROOT/build"; VAULT_ROOT="$TMP_ROOT/vault"; UV_CACHE_DIR="$TMP_ROOT/uv-cache"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$HERMES_HOME" "$BUILD_ROOT" "$VAULT_ROOT" "$UV_CACHE_DIR" "$DOCKER_CONFIG"
SAFE_PATH="$ROOT/.venv/bin:/usr/local/bin:/usr/bin:/bin"
BUN_BIN=""; UV_BIN=""; DOCKER_BIN=""
STAGED_TOOLS_DIR=""
LIFEDB_SETUP_UV_PATH=${LIFEDB_SETUP_UV_PATH:-}
if [[ -n "$LIFEDB_SETUP_UV_PATH" ]]; then
  [[ "$LIFEDB_SETUP_UV_PATH" == /* && -f "$LIFEDB_SETUP_UV_PATH" && ! -L "$LIFEDB_SETUP_UV_PATH" && -x "$LIFEDB_SETUP_UV_PATH" ]] || { printf 'unsafe uv source\n' >&2; exit 127; }
  STAGED_TOOLS_DIR=$(mktemp -d "$TMP_ROOT/tools.XXXXXX")
  chmod 700 "$STAGED_TOOLS_DIR"
  cp -- "$LIFEDB_SETUP_UV_PATH" "$STAGED_TOOLS_DIR/uv"
  chmod 700 "$STAGED_TOOLS_DIR/uv"
  SAFE_PATH="$STAGED_TOOLS_DIR:$SAFE_PATH"
fi
CLEANUP_STARTED=0

account_home() { getent passwd "$(id -u)" | cut -d: -f6; }
approved_root() {
  local path=$1 home
  home=$(account_home)
  [[ -n "$STAGED_TOOLS_DIR" && "$path" == "$STAGED_TOOLS_DIR/"* || "$path" == /bin/* || "$path" == /usr/bin/* || "$path" == /usr/local/bin/* || "$path" == "$home/.local/bin/"* || "$path" == "$home/.bun/bin/"* ]]
}
resolve_tool() {
  local name=$1 entry candidate canonical
  IFS=: read -ra entries <<< "${PATH:-}"
  for entry in "${entries[@]}"; do
    [[ -n "$entry" && "$entry" == /* ]] || { printf 'unsafe PATH entry\n' >&2; return 1; }
    candidate="$entry/$name"
    if [[ -e "$candidate" ]]; then
      [[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]] || { printf 'unapproved tool: %s\n' "$candidate" >&2; return 1; }
      canonical=$(readlink -f -- "$candidate") || return 1
      approved_root "$canonical" || { printf 'unapproved tool: %s\n' "$candidate" >&2; return 1; }
      local mode
      mode=$(stat -c %a -- "$(dirname "$canonical")")
      [[ "${mode: -2:1}" != [2367] && "${mode: -1}" != [2367] ]] || { printf 'unsafe tool permissions\n' >&2; return 1; }
      [[ $(stat -c %u -- "$canonical") -eq $(id -u) || "$canonical" == /bin/* || "$canonical" == /usr/bin/* || "$canonical" == /usr/local/bin/* ]] || { printf 'unsafe tool owner\n' >&2; return 1; }
      printf '%s\n' "$canonical"; return 0
    fi
  done
  return 1
}
clean_env() {
  env -i HOME="$HOME" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" HERMES_HOME="$HERMES_HOME" BUILD_ROOT="$BUILD_ROOT" VAULT_ROOT="$VAULT_ROOT" UV_CACHE_DIR="$UV_CACHE_DIR" TMPDIR="$TMP_ROOT" DOCKER_CONFIG="$DOCKER_CONFIG" PATH="$SAFE_PATH" LANG=C LC_ALL=C CI=true "$@"
}
cleanup() {
  local status=$? id actual owner
  [[ "$CLEANUP_STARTED" == 0 ]] || return "$status"
  CLEANUP_STARTED=1; trap - INT TERM EXIT
  if [[ -n "$DOCKER_BIN" ]]; then
    for id in "${CONTAINER_IDS[@]}"; do
      owner=$(clean_env "$DOCKER_BIN" container inspect --format '{{index .Config.Labels "com.lifedb.ci.owner"}}' "$id" 2>/dev/null) || continue
      [[ "$owner" == "$OWNER_TOKEN" ]] && clean_env "$DOCKER_BIN" container rm --force "$id" >/dev/null 2>&1 || :
    done
    for id in "${CONTAINER_NAMES[@]}"; do
      actual=$(clean_env "$DOCKER_BIN" container inspect --format '{{.Id}} {{index .Config.Labels "com.lifedb.ci.owner"}}' "$id" 2>/dev/null) || continue
      owner=${actual#* }; actual=${actual%% *}
      [[ "$owner" == "$OWNER_TOKEN" ]] && clean_env "$DOCKER_BIN" container rm --force "$actual" >/dev/null 2>&1 || :
    done
    if [[ -n "$IMAGE_ID" ]]; then
      owner=$(clean_env "$DOCKER_BIN" image inspect --format '{{index .Config.Labels "com.lifedb.ci.owner"}}' "$IMAGE_ID" 2>/dev/null) || owner=""
      [[ "$owner" == "$OWNER_TOKEN" ]] && clean_env "$DOCKER_BIN" image rm "$IMAGE_ID" >/dev/null 2>&1 || :
    fi
  fi
  rm -rf -- "$TMP_ROOT"
  return "$status"
}
interrupt() { cleanup; exit 143; }
trap cleanup EXIT; trap interrupt INT TERM
docker_cmd() { clean_env "$DOCKER_BIN" "$@"; }
run_python() { clean_env "$PYTHON_BIN" "$@"; }

python_stage() { BUN_BIN=$(resolve_tool bun) || return 127; SAFE_PATH="$(dirname "$BUN_BIN"):$SAFE_PATH"; [[ "$(clean_env "$BUN_BIN" --version)" == 1.4.0 ]] || return 1; [[ -x "$PYTHON_BIN" ]] || return 127; (cd "$ROOT/integrations/opencode" && clean_env "$BUN_BIN" ci); (cd "$ROOT" && clean_env PYTHONPATH=src "$PYTHON_BIN" -m unittest discover -s tests -v); (cd "$ROOT" && clean_env PYTHONPATH=src "$PYTHON_BIN" -m compileall -q src tests integrations/hermes); }
opencode_stage() { BUN_BIN=$(resolve_tool bun) || return 127; SAFE_PATH="$(dirname "$BUN_BIN"):$SAFE_PATH"; [[ "$(clean_env "$BUN_BIN" --version)" == 1.4.0 ]] || return 1; (cd "$ROOT/integrations/opencode" && clean_env "$BUN_BIN" -e 'const p = await Bun.file("package.json").json(); if (p.devDependencies["@opencode-ai/plugin"] !== "1.18.29" || p.devDependencies["@opencode-ai/sdk"] !== "1.18.29") process.exit(1)' && clean_env "$BUN_BIN" ci && clean_env "$BUN_BIN" test && clean_env "$BUN_BIN" run typecheck); }
hermes_stage() { (cd "$ROOT" && clean_env PYTHONPATH=. "$PYTHON_BIN" -m unittest discover -s integrations/hermes/tests -v); }
package_stage() { if [[ -n "$STAGED_TOOLS_DIR" ]]; then UV_BIN=$(PATH="$SAFE_PATH" resolve_tool uv) || return 127; else UV_BIN=$(resolve_tool uv) || return 127; fi; SAFE_PATH="$(dirname "$UV_BIN"):$SAFE_PATH"; rm -rf -- "$BUILD_ROOT"; mkdir -p "$BUILD_ROOT"; clean_env "$UV_BIN" build --wheel --sdist --out-dir "$BUILD_ROOT" "$ROOT"; (cd "$ROOT" && clean_env "$PYTHON_BIN" scripts/check-package-artifacts.py "$BUILD_ROOT"); for artifact in "$BUILD_ROOT"/*.whl "$BUILD_ROOT"/*.tar.gz; do label=sdist; [[ "$artifact" == *.whl ]] && label=wheel; env_root="$TMP_ROOT/env-$label"; vault="$TMP_ROOT/vault-$label"; clean_env "$UV_BIN" venv --python "$PYTHON_BIN" "$env_root"; clean_env "$UV_BIN" pip install --python "$env_root/bin/python" "$artifact"; clean_env "$env_root/bin/lifedb" --vault "$vault" init; printf '%s' 'fresh install recoverable' | clean_env "$env_root/bin/lifedb" --vault "$vault" ingest - --media-type text/plain; clean_env "$env_root/bin/lifedb" --vault "$vault" validate; clean_env "$env_root/bin/lifedb" --vault "$vault" rebuild; clean_env "$env_root/bin/lifedb" --vault "$vault" search recoverable; done; }
docker_create() { local name=$1 id; shift; if docker_cmd container inspect "$name" >/dev/null 2>&1; then return 1; fi; CONTAINER_NAMES+=("$name"); id=$(docker_cmd container create --name "$name" --label "com.lifedb.ci.owner=$OWNER_TOKEN" --label com.lifedb.ci.kind=container "${RUN_ARGS[@]}" "$IMAGE_ID" "$@"); [[ "$(docker_cmd container inspect --format '{{.Id}} {{index .Config.Labels "com.lifedb.ci.owner"}}' "$id")" == "$id $OWNER_TOKEN" ]] || return 1; CONTAINER_IDS+=("$id"); LAST_ID="$id"; }
docker_wait() { local id=$1 rc; docker_cmd container start "$id" >/dev/null; rc=$(docker_cmd container wait "$id") || return 1; [[ "$rc" == 0 ]] || return "$rc"; }
docker_stage() { DOCKER_BIN=$(resolve_tool docker) || return 127; SAFE_PATH="$(dirname "$DOCKER_BIN"):$SAFE_PATH"; if docker_cmd image inspect "$IMAGE_TAG" >/dev/null 2>&1; then return 1; fi; docker_cmd build --label "com.lifedb.ci.owner=$OWNER_TOKEN" --label com.lifedb.ci.kind=image --tag "$IMAGE_TAG" "$ROOT"; IMAGE_ID=$(docker_cmd image inspect --format '{{.Id}}' "$IMAGE_TAG"); [[ "$(docker_cmd image inspect --format '{{index .Config.Labels "com.lifedb.ci.owner"}}' "$IMAGE_ID")" == "$OWNER_TOKEN" ]] || return 1; RUN_ARGS=(--read-only --tmpfs /tmp:size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" -v "$VAULT_ROOT:/data"); docker_create "${CONTAINER_PREFIX}-init" init; docker_wait "$LAST_ID"; docker_create "${CONTAINER_PREFIX}-ingest" ingest - --media-type text/plain; printf '%s' 'recoverable memory' | docker_cmd container start -ai "$LAST_ID"; docker_create "${CONTAINER_PREFIX}-validate" validate; docker_wait "$LAST_ID"; docker_create "${CONTAINER_PREFIX}-reset" runtime reset --confirm DELETE-RUNTIME; docker_wait "$LAST_ID"; docker_create "${CONTAINER_PREFIX}-rebuild" rebuild; docker_wait "$LAST_ID"; docker_create "${CONTAINER_PREFIX}-validate2" validate; docker_wait "$LAST_ID"; docker_create "${CONTAINER_PREFIX}-search" search recoverable; docker_wait "$LAST_ID"; }
case "$STAGE" in python) python_stage;; opencode) opencode_stage;; hermes) hermes_stage;; package-smoke) package_stage;; docker) docker_stage;; all) python_stage; opencode_stage; hermes_stage; package_stage; docker_stage;; *) printf 'Unknown stage: %s\n' "$STAGE" >&2; exit 2;; esac
