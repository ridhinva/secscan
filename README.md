# secscan - Unified Security Scanner Orchestrator

<p align="center">
  <a href="https://github.com/ridhinva/secscan/stargazers"><img src="https://img.shields.io/github/stars/ridhinva/secscan?style=for-the-badge" alt="Stars"></a>
  <a href="https://github.com/ridhinva/secscan/network/members"><img src="https://img.shields.io/github/forks/ridhinva/secscan?style=for-the-badge" alt="Forks"></a>
  <a href="https://github.com/ridhinva/secscan/issues"><img src="https://img.shields.io/github/issues/ridhinva/secscan?style=for-the-badge" alt="Issues"></a>
  <a href="https://github.com/ridhinva/secscan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ridhinva/secscan?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/ridhinva/secscan/commits/main"><img src="https://img.shields.io/github/last-commit/ridhinva/secscan?style=for-the-badge" alt="Last Commit"></a>
  <a href="https://github.com/ridhinva/secscan/actions"><img src="https://img.shields.io/github/actions/workflow/status/ridhinva/secscan/ci.yml?style=for-the-badge" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/Tools-64-critical?style=for-the-badge" alt="64 Tools">
  <img src="https://img.shields.io/badge/SARIF-Supported-success?style=for-the-badge" alt="SARIF">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Platform">
</p>

---

## 🎯 Overview

**Unified security scanner orchestrator** for 64 specialized security tools. Runs CVE scanners, AI/LLM security, API security, supply chain, Kubernetes, identity, ransomware, Web3, mobile/IoT, zero trust, AI agent, and recon tools in parallel with SARIF/JSON/HTML output.

| Category | Tools | Examples |
|----------|-------|----------|
| **CVE/Exploit** | 12 | PAN-OS RCE, CISA KEV, Drupal SQLi, BeyondTrust, GHE, Defender, LiteLLM, Android ADB, Langflow, Linux kernel, npm tar |
| **AI/LLM Security** | 1 | OWASP LLM Top 10 2024 (prompt injection, RAG poisoning, agent hijacking) |
| **API Security** | 1 | OWASP API Top 10 + GraphQL (BOLA, BFLA, SSRF, introspection) |
| **Supply Chain** | 1 | Dependency confusion, typosquatting, CI/CD injection, SBOM |
| **Kubernetes** | 1 | RBAC escalation, container escape, admission controller, ETCD |
| **Identity/Auth** | 1 | Okta MFA bypass, Entra ID tokens, OAuth device code, SAML, Kerberos |
| **Ransomware** | 1 | Behavior detection, encryption patterns, shadow copy, backup targeting |
| **Web3/DeFi** | 1 | Reentrancy, oracle manipulation, flash loans, cross-chain |
| **Mobile/IoT** | 1 | Android exported, iOS URL schemes, BLE, MQTT/CoAP, firmware |
| **Zero Trust** | 1 | ZTNA config, device posture, microsegmentation, continuous verification |
| **AI Agent** | 1 | Goal hijacking, tool misuse, context poisoning, sandbox escape |
| **Recon/OSINT** | 10 | GitHub secrets, netrecon, subdomain, DNS, headers, OSINT, WHOIS, SSL, port, packet, logs |
| **Toolkits** | 8 | API, Cloud, Mobile, Infra, Web, Wireless, Crypto, Exploit Dev, Reversing, OSINT |
| **Other** | 15 | Crypto, Exploit Dev, Reversing, Hardware, Wireless, AI Framework, Comms, etc. |

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/ridhinva/secscan.git
cd secscan
pip install requests pyyaml
```

### Usage

#### Scan all available tools
```bash
# Clone all 64 tool repos first (or place them in ./tools/)
mkdir tools && cd tools
# git clone https://github.com/ridhinva/panos-captive-portal-rce.git
# git clone https://github.com/ridhinva/llm-security-scanner.git
# ... etc

# Run secscan from parent directory
cd ..
python3 secscan.py --tools-dir ./tools --target https://api.example.com --api-key YOUR_KEY
```

#### Scan specific category
```bash
# Only CVE scanners
python3 secscan.py --tools-dir ./tools --category cve --target https://target.com

# Only AI/LLM security
python3 secscan.py --tools-dir ./tools --category ai --target https://api.openai.com/v1/chat/completions --api-key YOUR_KEY

# Only API security
python3 secscan.py --tools-dir ./tools --category api --target https://api.example.com --auth "Bearer TOKEN"
```

#### Scan specific tools
```bash
python3 secscan.py --tools-dir ./tools --tools panos-captive-portal-rce llm-security-scanner api-security-scanner --target https://target.com
```

#### Generate reports
```bash
# SARIF (for GitHub Code Scanning, VS Code, etc.)
python3 secscan.py --tools-dir ./tools --target https://target.com --output results.sarif --format sarif

# JSON
python3 secscan.py --tools-dir ./tools --target https://target.com --output results.json

# HTML
python3 secscan.py --tools-dir ./tools --target https://target.com --output report.html --format html
```

#### CI/CD Integration (GitHub Actions)
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request, schedule]
jobs:
  secscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Clone tools
        run: |
          mkdir tools
          cd tools
          # Add tool repos as submodules or clone here
      - name: Run secscan
        run: |
          python3 secscan.py --tools-dir ./tools --target ${{ secrets.TARGET_URL }} --api-key ${{ secrets.API_KEY }} --output results.sarif --format sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

---

## 📋 Tool Registry (64 Tools)

<details>
<summary>Click to expand full tool list</summary>

| Tool | Category | Type | Args |
|------|----------|------|------|
| panos-captive-portal-rce | cve | scanner | --target |
| cisa-kev-exploit-scanners | cve | scanner | --target |
| drupal-jsonapi-sqli-scanner | cve | scanner | --target |
| beyondtrust-rce-scanner | cve | scanner | --target |
| ghe-push-option-rce-scanner | cve | scanner | --target |
| defender-privilege-escalation-scanner | cve | scanner | --target |
| litellm-sqli-scanner | cve | scanner | --target |
| android-adb-bypass-scanner | cve | scanner | --target |
| langflow-cors-scanner | cve | scanner | --target |
| linux-kernel-algif-aead-checker | cve | scanner | --target |
| npm-tar-path-traversal-scanner | cve | scanner | --target |
| trending-cve-scanners | cve | scanner | --target |
| llm-security-scanner | ai | scanner | --target --api-key --model |
| api-security-scanner | api | scanner | --target --auth |
| supply-chain-scanner | supply-chain | scanner | --target --mode |
| k8s-security-toolkit | kubernetes | toolkit | --target --kubeconfig --mode |
| identity-auth-scanner | identity | scanner | --target --mode |
| ransomware-behavior-detector | ransomware | detector | --target --mode |
| web3-defi-scanner | web3 | scanner | --rpc --contract --mode |
| mobile-iot-scanner | mobile | scanner | --target --mode |
| zero-trust-assessor | zero-trust | tool | --config --mode |
| ai-agent-security-scanner | ai-agent | scanner | --target --framework --mode |
| github-secret-scanner | osint | scanner | --target |
| netrecon | recon | scanner | --target |
| subdomain-finder | recon | scanner | --target |
| dns-tools | recon | toolkit | (repo) |
| headers-analyzer | recon | scanner | --target |
| osint-finder | osint | scanner | --target |
| whois-lookup | recon | scanner | --target |
| ssl-scanner | recon | scanner | --target |
| port-scanner | recon | scanner | --target |
| packet-sniffer | recon | scanner | --target |
| log-analyzer | recon | scanner | --target |
| hash-cracker | crypto | scanner | --target |
| haveibeenpwned | crypto | tool | --target |
| pass-audit | crypto | scanner | --target |
| vuln-scanner | exploit-dev | scanner | --target |
| wifi-audit | wireless | scanner | --target |
| TwitterScraper | osint | scraper | --query |

</details>

---

## 📊 Output Formats

### SARIF (v2.1.0)
Compatible with: GitHub Code Scanning, VS Code SARIF Viewer, Azure DevOps, GitLab, SonarQube
```bash
python3 secscan.py --tools-dir ./tools --target https://target.com --output results.sarif --format sarif
```

### JSON
Complete scan data with all findings, metadata, and timing
```bash
python3 secscan.py --tools-dir ./tools --target https://target.com --output results.json
```

### HTML
Self-contained report with collapsible findings, severity colors, searchable
```bash
python3 secscan.py --tools-dir ./tools --target https://target.com --output report.html --format html
```

---

## ⚙️ Configuration

### Tool Arguments (passed to all applicable tools)
| Arg | Tools | Description |
|-----|-------|-------------|
| `--target` | Most scanners | Target URL, IP, file, contract |
| `--api-key` | LLM, API tools | API key for authentication |
| `--auth` | API scanners | Auth header (Bearer, API key) |
| `--model` | LLM tools | Model name (default: gpt-3.5-turbo) |
| `--rpc` | Web3 tools | RPC endpoint URL |
| `--contract` | Web3 tools | Contract address |
| `--kubeconfig` | K8s tools | Path to kubeconfig |
| `--config` | Zero Trust tools | YAML config file |
| `--framework` | AI Agent tools | langchain/langgraph/autogen/crewai/custom |
| `--mode` | Multi-mode tools | Specific mode or "all" |

---

## 🔧 Requirements

- Python 3.10+
- `requests`, `pyyaml`
- Tool repos cloned in `--tools-dir` (or installed as packages)

```bash
pip install requests pyyaml
# Optional for specific tools:
pip install web3 watchdog frida-tools
```

---

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**[@c_y_p_h3r](https://x.com/c_y_p_h3r)** — Bug bounty hunter & security researcher

---

## 🤝 Contributing

1. Fork → Branch → Add tool to `TOOL_REGISTRY` → Test → PR
2. Follow conventional commits
3. Add tool-specific tests

---

## 📚 Related Projects

- [llm-security-scanner](https://github.com/ridhinva/llm-security-scanner) — OWASP LLM Top 10 2024
- [api-security-scanner](https://github.com/ridhinva/api-security-scanner) — OWASP API Top 10 + GraphQL
- [VulnHunterAI](https://github.com/ridhinva/VulnHunterAI) — Autonomous AI pentest framework