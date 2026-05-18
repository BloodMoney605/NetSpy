#!/usr/bin/env bash
set -euo pipefail

echo "[+] NetSPy installer"
echo "    target: $(uname -m)-$(uname -s)"

# -- System packages --
PKGS=(
    nmap
    curl
    dnsutils
    whois
    jq
    whatweb
    openssl
)

echo "[*] installing system packages..."
sudo apt update -qq
sudo apt install -y -qq "${PKGS[@]}"
echo "    done."

# -- Go tools --
GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

echo "[*] ensuring Go is available..."
if ! command -v go &>/dev/null; then
    echo "    [!] Go not found. installing..."
    wget -q https://go.dev/dl/go1.22.3.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    rm /tmp/go.tar.gz
fi

echo "[*] installing Go tools..."
for tool in "${GO_TOOLS[@]}"; do
    echo -n "    $tool ... "
    go install "$tool" 2>/dev/null && echo "ok" || echo "skip"
done

# -- Python packages --
PY_PKGS=(
    pyyaml
    requests
    jinja2
)

echo "[*] installing Python packages..."
pip3 install -q "${PY_PKGS[@]}"
echo "    done."

# -- Nuclei templates --
echo "[*] updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update -ut > /dev/null 2>&1 || true
fi

# -- Data directory --
echo "[*] creating data directory..."
mkdir -p ~/.netspy

# -- Add netspy to PATH --
echo "[*] linking netspy to /usr/local/bin..."
sudo ln -sf "$(pwd)/netspy" /usr/local/bin/netspy

echo
echo "[+] installation complete."
echo "    run: netspy audit --domain example.com"
