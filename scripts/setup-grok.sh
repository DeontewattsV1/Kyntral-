#!/usr/bin/env bash
set -euo pipefail

# Official npm distribution; avoids piping an unversioned installer into bash.
readonly grok_version='1.0.70'
command -v npm >/dev/null || { echo 'Node.js 20+ and npm are required.' >&2; exit 1; }
npm install --global "@xai-official/grok@${grok_version}"

grok_config_dir="${GROK_HOME:-${HOME}/.grok}"
mkdir -p "${grok_config_dir}"
chmod 700 "${grok_config_dir}"
if [[ ! -e "${grok_config_dir}/config.toml" ]]; then
  (umask 077; cat > "${grok_config_dir}/config.toml" <<'TOML'
[cli]
auto_update = false

[models]
default = "grok-4.6"
TOML
  )
fi

grok_prefix=$(npm prefix --global)
grok_bin="${grok_prefix}/bin/grok"
"${grok_bin}" --version

if ! command -v grok >/dev/null; then
  printf 'Add this directory to PATH: %s/bin\n' "${grok_prefix}"
fi
if [[ -z "${XAI_API_KEY:-}" ]]; then
  echo 'Installed and configured. Set XAI_API_KEY in your environment to authenticate.'
else
  echo 'Installed and configured. XAI_API_KEY is set; no paid API request was made.'
fi
