#!/usr/bin/env python3
"""
secscan - Unified Security Scanner Orchestrator
Routes to all 64 security tools, handles auth, aggregates results in SARIF/JSON
"""
import sys, json, argparse, subprocess, os, importlib.util, importlib.machinery
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.0.0"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                    secscan v1.0 - Unified Security Orchestrator ║
║         64 Security Tools | SARIF/JSON Output | CI/CD Ready    ║
╚══════════════════════════════════════════════════════════════╝
"""

# Tool registry: maps tool name to module info
TOOL_REGISTRY = {
    # CVE Scanners
    "panos-captive-portal-rce": {"module": "panos_rce_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "cisa-kev-exploit-scanners": {"module": "trending_scanner", "type": "scanner", "category": "cve", "args": ["--target"], "path": "scanners/"},
    "drupal-jsonapi-sqli-scanner": {"module": "drupal_jsonapi_sqli_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "beyondtrust-rce-scanner": {"module": "beyondtrust_rce_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "ghe-push-option-rce-scanner": {"module": "ghe_push_option_rce_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "defender-privilege-escalation-scanner": {"module": "defender_privilege_escalation_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "litellm-sqli-scanner": {"module": "litellm_sqli_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "android-adb-bypass-scanner": {"module": "android_adb_bypass_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "langflow-cors-scanner": {"module": "langflow_cors_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "linux-kernel-algif-aead-checker": {"module": "linux_kernel_algif_aead_checker", "type": "scanner", "category": "cve", "args": ["--target"]},
    "npm-tar-path-traversal-scanner": {"module": "npm_tar_path_traversal_scanner", "type": "scanner", "category": "cve", "args": ["--target"]},
    "trending-cve-scanners": {"module": "trending_scanner", "type": "scanner", "category": "cve", "args": ["--target"], "path": "scanners/"},
    
    # AI/LLM Security
    "llm-security-scanner": {"module": "llm_security_scanner", "type": "scanner", "category": "ai", "args": ["--target", "--api-key", "--model"]},
    
    # API Security
    "api-security-scanner": {"module": "api_security_scanner", "type": "scanner", "category": "api", "args": ["--target", "--auth"]},
    
    # Supply Chain
    "supply-chain-scanner": {"module": "supply_chain_scanner", "type": "scanner", "category": "supply-chain", "args": ["--target", "--mode"]},
    
    # Kubernetes
    "k8s-security-toolkit": {"module": "k8s_security_toolkit", "type": "toolkit", "category": "kubernetes", "args": ["--target", "--kubeconfig", "--mode"]},
    
    # Identity/Auth
    "identity-auth-scanner": {"module": "identity_auth_scanner", "type": "scanner", "category": "identity", "args": ["--target", "--mode"]},
    
    # Ransomware
    "ransomware-behavior-detector": {"module": "ransomware_detector", "type": "detector", "category": "ransomware", "args": ["--target", "--mode"]},
    
    # Web3/DeFi
    "web3-defi-scanner": {"module": "web3_defi_scanner", "type": "scanner", "category": "web3", "args": ["--rpc", "--contract", "--mode"]},
    
    # Mobile/IoT
    "mobile-iot-scanner": {"module": "mobile_iot_scanner", "type": "scanner", "category": "mobile", "args": ["--target", "--mode"]},
    
    # Zero Trust
    "zero-trust-assessor": {"module": "zero_trust_assessor", "type": "tool", "category": "zero-trust", "args": ["--config", "--mode"]},
    
    # AI Agent
    "ai-agent-security-scanner": {"module": "ai_agent_scanner", "type": "scanner", "category": "ai-agent", "args": ["--target", "--framework", "--mode"]},
    
    # Toolkits
    "API-Security-Toolkit": {"type": "toolkit", "category": "api", "repo": True},
    "Cloud-Security-Toolkit": {"type": "toolkit", "category": "cloud", "repo": True},
    "Mobile-Security-Toolkit": {"type": "toolkit", "category": "mobile", "repo": True},
    "Infra-Security-Toolkit": {"type": "toolkit", "category": "infra", "repo": True},
    "Web-Security-Toolkit": {"type": "toolkit", "category": "web", "repo": True},
    "Wireless-Security-Toolkit": {"type": "toolkit", "category": "wireless", "repo": True},
    "Crypto-Attack-Toolkit": {"type": "toolkit", "category": "crypto", "repo": True},
    "Exploit-Dev-Toolkit": {"type": "toolkit", "category": "exploit-dev", "repo": True},
    "Reversing-Toolkit": {"type": "toolkit", "category": "reversing", "repo": True},
    "OSINT-Toolkit": {"type": "toolkit", "category": "osint", "repo": True},
    
    # Recon/OSINT
    "OSINT-Toolkit": {"type": "toolkit", "category": "osint", "repo": True},
    "github-secret-scanner": {"module": "github_secret_scanner", "type": "scanner", "category": "osint", "args": ["--target"]},
    "netrecon": {"module": "netrecon", "type": "scanner", "category": "recon", "args": ["--target"]},
    "subdomain-finder": {"module": "subdomain_finder", "type": "scanner", "category": "recon", "args": ["--target"]},
    "dns-tools": {"module": "dns_tools", "type": "toolkit", "category": "recon", "repo": True},
    "headers-analyzer": {"module": "headers_analyzer", "type": "scanner", "category": "recon", "args": ["--target"]},
    "osint-finder": {"module": "osint_finder", "type": "scanner", "category": "osint", "args": ["--target"]},
    "whois-lookup": {"module": "whois_lookup", "type": "scanner", "category": "recon", "args": ["--target"]},
    "ssl-scanner": {"module": "ssl_scanner", "type": "scanner", "category": "recon", "args": ["--target"]},
    "port-scanner": {"module": "port_scanner", "type": "scanner", "category": "recon", "args": ["--target"]},
    "packet-sniffer": {"module": "packet_sniffer", "type": "scanner", "category": "recon", "args": ["--target"]},
    "log-analyzer": {"module": "log_analyzer", "type": "scanner", "category": "recon", "args": ["--target"]},
    
    # Crypto
    "Crypto-Attack-Toolkit": {"type": "toolkit", "category": "crypto", "repo": True},
    "hash-cracker": {"module": "hash_cracker", "type": "scanner", "category": "crypto", "args": ["--target"]},
    "haveibeenpwned": {"module": "haveibeenpwned", "type": "tool", "category": "crypto", "args": ["--target"]},
    "pass-audit": {"module": "pass_audit", "type": "scanner", "category": "crypto", "args": ["--target"]},
    
    # Exploit Dev
    "Exploit-Dev-Toolkit": {"type": "toolkit", "category": "exploit-dev", "repo": True},
    "vuln-scanner": {"module": "vuln_scanner", "type": "scanner", "category": "exploit-dev", "args": ["--target"]},
    
    # Reversing
    "Reversing-Toolkit": {"type": "toolkit", "category": "reversing", "repo": True},
    
    # Hardware/Wireless
    "flipperwire": {"type": "toolkit", "category": "hardware", "repo": True},
    "ghostwire": {"type": "toolkit", "category": "hardware", "repo": True},
    "pocket-s": {"type": "toolkit", "category": "hardware", "repo": True},
    "usbrubberducky-payloads": {"type": "payloads", "category": "hardware", "repo": True},
    "wifi-audit": {"module": "wifi_audit", "type": "scanner", "category": "wireless", "args": ["--target"]},
    "Wireless-Security-Toolkit": {"type": "toolkit", "category": "wireless", "repo": True},
    
    # Mobile
    "Mobile-Security-Toolkit": {"type": "toolkit", "category": "mobile", "repo": True},
    
    # Other
    "VulnHunterAI": {"type": "framework", "category": "ai-framework", "repo": True},
    "ds4": {"type": "inference", "category": "ai", "repo": True},
    "OnyxChat": {"type": "app", "category": "comms", "repo": True},
    "TwitterScraper": {"module": "TwitterScraper", "type": "scraper", "category": "osint", "args": ["--query"]},
    "tvaxkva": {"type": "utility", "category": "utility", "repo": True},
    "Portfolio": {"type": "web", "category": "portfolio", "repo": True},
    "spaceship-prompt": {"type": "utility", "category": "shell", "repo": True},
    "home": {"type": "config", "category": "config", "repo": True},
    "github-secret-findings": {"type": "data", "category": "findings", "repo": True},
    "JustSaying": {"type": "library", "category": "messaging", "repo": True},
}

CATEGORIES = {
    "cve": "CVE/Exploit Scanners",
    "ai": "AI/LLM Security",
    "api": "API Security",
    "supply-chain": "Supply Chain",
    "kubernetes": "Kubernetes/Cloud",
    "identity": "Identity/Auth",
    "ransomware": "Ransomware",
    "web3": "Web3/DeFi",
    "mobile": "Mobile/IoT",
    "zero-trust": "Zero Trust",
    "ai-agent": "AI Agent",
    "recon": "Recon/OSINT",
    "osint": "OSINT",
    "crypto": "Cryptography",
    "exploit-dev": "Exploit Development",
    "reversing": "Reverse Engineering",
    "hardware": "Hardware/Wireless",
    "wireless": "Wireless",
    "ai-framework": "AI Framework",
    "findings": "Findings/Data",
    "messaging": "Messaging",
    "portfolio": "Portfolio",
    "config": "Config",
    "shell": "Shell",
    "utility": "Utility",
}

class SecScan:
    def __init__(self, tools_dir=".", config=None):
        self.tools_dir = Path(tools_dir).resolve()
        self.config = config or {}
        self.results = {}
        self.errors = {}
        
    def discover_tools(self):
        """Auto-discover available tools in tools_dir"""
        discovered = {}
        for tool_name, info in TOOL_REGISTRY.items():
            if info.get("repo"):
                # Check if repo exists
                repo_path = self.tools_dir / tool_name
                if repo_path.exists():
                    discovered[tool_name] = {**info, "available": True, "path": str(repo_path)}
                else:
                    discovered[tool_name] = {**info, "available": False, "reason": "repo not cloned"}
            elif info.get("module"):
                # Check if Python module exists
                module_path = info.get("path", "") + info["module"].replace(".", "/") + ".py"
                full_path = self.tools_dir / module_path
                if full_path.exists():
                    discovered[tool_name] = {**info, "available": True, "path": str(full_path)}
                else:
                    # Try direct in tools_dir
                    direct_path = self.tools_dir / f"{info['module']}.py"
                    if direct_path.exists():
                        discovered[tool_name] = {**info, "available": True, "path": str(direct_path)}
                    else:
                        discovered[tool_name] = {**info, "available": False, "reason": "module not found"}
            else:
                discovered[tool_name] = {**info, "available": False, "reason": "no module or repo"}
        return discovered
    
    def run_tool(self, tool_name, tool_info, args, timeout=300):
        """Run a single tool and return structured results"""
        if not tool_info.get("available"):
            return {"tool": tool_name, "status": "skipped", "reason": tool_info.get("reason", "not available"), "findings": {}}
        
        try:
            if tool_info.get("repo"):
                # Run as subprocess
                cmd = self._build_repo_cmd(tool_name, tool_info, args)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=self.tools_dir / tool_name)
                return self._parse_output(tool_name, result, tool_info)
            else:
                # Import and run Python module
                return self._run_python_module(tool_name, tool_info, args)
        except subprocess.TimeoutExpired:
            return {"tool": tool_name, "status": "timeout", "error": f"Exceeded {timeout}s", "findings": {}}
        except Exception as e:
            return {"tool": tool_name, "status": "error", "error": str(e), "findings": {}}
    
    def _build_repo_cmd(self, tool_name, tool_info, args):
        """Build command for repo-based tools"""
        # Heuristic: look for main.py, cli.py, or tool_name.py
        repo_path = self.tools_dir / tool_name
        possible_entries = [
            "main.py", "cli.py", f"{tool_name}.py", f"{tool_name.replace('-', '_')}.py",
            "scanner.py", "tool.py", "run.py"
        ]
        entry = None
        for e in possible_entries:
            if (repo_path / e).exists():
                entry = e
                break
        if not entry:
            entry = "main.py"  # fallback
        
        cmd = ["python3", entry]
        # Add args based on tool type
        for arg_def in tool_info.get("args", []):
            if arg_def.startswith("--"):
                # Check if arg value provided in args
                arg_name = arg_def.lstrip("-")
                if arg_name in args:
                    cmd.extend([arg_def, args[arg_name]])
        return cmd
    
    def _parse_output(self, tool_name, result, tool_info):
        """Parse tool output into standardized format"""
        output = result.stdout
        stderr = result.stderr
        rc = result.returncode
        
        findings = {}
        try:
            # Try to parse JSON output
            findings = json.loads(output.strip().split('\n')[-1])
        except:
            # Fallback: parse text output
            findings = {"raw_output": output[-2000:] if output else stderr[-2000:]}
        
        return {
            "tool": tool_name,
            "status": "success" if rc == 0 else "failed",
            "exit_code": rc,
            "findings": findings,
            "category": tool_info.get("category", "unknown"),
            "type": tool_info.get("type", "unknown")
        }
    
    def _run_python_module(self, tool_name, tool_info, args):
        """Import and run Python module directly"""
        module_path = tool_info["path"]
        spec = importlib.util.spec_from_file_location(tool_info["module"], module_path)
        module = importlib.util.module_from_spec(spec)
        
        # Capture stdout
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        
        try:
            spec.loader.exec_module(module)
            # Call main if exists
            if hasattr(module, "main"):
                # Prepare sys.argv
                old_argv = sys.argv
                sys.argv = [tool_info["module"]] + self._flatten_args(args)
                try:
                    module.main()
                except SystemExit:
                    pass
                finally:
                    sys.argv = old_argv
            output = captured.getvalue()
        except Exception as e:
            output = f"Error: {e}"
        finally:
            sys.stdout = old_stdout
        
        try:
            findings = json.loads(output.strip().split('\n')[-1])
        except:
            findings = {"raw_output": output[-2000:]}
        
        return {
            "tool": tool_name,
            "status": "success",
            "findings": findings,
            "category": tool_info.get("category", "unknown"),
            "type": tool_info.get("type", "unknown")
        }
    
    def _flatten_args(self, args):
        """Convert dict args to argv list"""
        argv = []
        for k, v in args.items():
            argv.extend([f"--{k}", str(v)])
        return argv
    
    def run_scan(self, tool_filter=None, category_filter=None, parallel=4, timeout=300):
        """Run scan across all or filtered tools"""
        discovered = self.discover_tools()
        
        # Filter tools
        tools_to_run = {}
        for name, info in discovered.items():
            if not info.get("available"):
                continue
            if tool_filter and name not in tool_filter:
                continue
            if category_filter and info.get("category") != category_filter:
                continue
            tools_to_run[name] = info
        
        print(f"[*] Discovered {len(discovered)} tools, running {len(tools_to_run)}")
        
        # Run tools
        results = {}
        with ThreadPoolExecutor(max_workers=parallel) as executor:
            future_to_tool = {
                executor.submit(self.run_tool, name, info, self.config.get("args", {})): name
                for name, info in tools_to_run.items()
            }
            
            for future in as_completed(future_to_tool):
                name = future_to_tool[future]
                try:
                    results[name] = future.result()
                    status = results[name]["status"]
                    cat = results[name].get("category", "?")
                    print(f"  [{status}] {name} ({cat})")
                except Exception as e:
                    results[name] = {"tool": name, "status": "error", "error": str(e), "findings": {}}
                    print(f"  [error] {name}: {e}")
        
        self.results = results
        return results
    
    def generate_sarif(self, output_file):
        """Generate SARIF report from results"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "secscan",
                        "version": VERSION,
                        "informationUri": "https://github.com/ridhinva/secscan",
                        "rules": []
                    }
                },
                "results": []
            }]
        }
        
        rule_map = {}
        rule_id = 0
        
        for tool_name, result in self.results.items():
            if result["status"] != "success":
                continue
            
            findings = result.get("findings", {})
            if isinstance(findings, dict):
                for finding_name, finding_data in findings.items():
                    if isinstance(finding_data, dict) and finding_data.get("vulnerable"):
                        rule_key = f"{tool_name}:{finding_name}"
                        if rule_key not in rule_map:
                            rule_map[rule_key] = rule_id
                            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                                "id": str(rule_id),
                                "name": rule_key,
                                "shortDescription": {"text": f"{tool_name} - {finding_name}"},
                                "fullDescription": {"text": str(finding_data.get("details", ["Vulnerability detected"])[0])},
                                "defaultConfiguration": {"level": "error" if "CRITICAL" in str(finding_data) else "warning"},
                                "properties": {"category": result.get("category"), "tool": tool_name}
                            })
                            rule_id += 1
                        
                        sarif["runs"][0]["results"].append({
                            "ruleId": str(rule_map[rule_key]),
                            "message": {"text": str(finding_data.get("details", ["Vulnerability detected"])[0])},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": tool_name},
                                    "region": {"startLine": 1}
                                }
                            }],
                            "properties": {"tool": tool_name, "finding": finding_name, "raw": finding_data}
                        })
        
        with open(output_file, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"[*] SARIF report saved to {output_file}")
    
    def generate_json(self, output_file):
        """Generate JSON report"""
        report = {
            "scanner": "secscan",
            "version": VERSION,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_tools": len(self.results),
                "successful": sum(1 for r in self.results.values() if r["status"] == "success"),
                "failed": sum(1 for r in self.results.values() if r["status"] in ["failed", "error"]),
                "skipped": sum(1 for r in self.results.values() if r["status"] == "skipped"),
                "vulnerable_categories": sum(1 for r in self.results.values() 
                    if r["status"] == "success" and isinstance(r.get("findings"), dict) 
                    and any(v.get("vulnerable") for v in r["findings"].values() if isinstance(v, dict)))
            },
            "results": self.results
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] JSON report saved to {output_file}")
    
    def generate_html(self, output_file):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html><head>
<title>secscan Report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC</title>
<style>
body {{ font-family: monospace; margin: 20px; background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; }}
.tool {{ border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 10px 0; background: #161b22; }}
.tool.success {{ border-left: 4px solid #3fb950; }}
.tool.failed {{ border-left: 4px solid #f85149; }}
.tool.skipped {{ border-left: 4px solid #8b949e; }}
.category {{ color: #a5d6ff; font-size: 0.9em; }}
.vuln {{ color: #f85149; }}
.secure {{ color: #3fb950; }}
pre {{ background: #010409; padding: 10px; border-radius: 6px; overflow: auto; }}
</style>
</head><body>
<h1>secscan Report</h1>
<p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Version: {VERSION}</p>
"""
        
        for tool_name, result in self.results.items():
            status = result["status"]
            cat = result.get("category", "unknown")
            html += f'<div class="tool {status}">\n'
            html += f'  <h3>{tool_name} <span class="category">[{cat}]</span></h3>\n'
            html += f'  <p>Status: <span class="{status}">{status.upper()}</span></p>\n'
            if result.get("error"):
                html += f'  <p class="vuln">Error: {result["error"]}</p>\n'
            findings = result.get("findings", {})
            if isinstance(findings, dict) and findings:
                html += f'  <h4>Findings:</h4>\n  <pre>{json.dumps(findings, indent=2)[:3000]}</pre>\n'
            html += '</div>\n'
        
        html += "</body></html>"
        with open(output_file, "w") as f:
            f.write(html)
        print(f"[*] HTML report saved to {output_file}")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="secscan - Unified Security Scanner Orchestrator")
    parser.add_argument("--tools-dir", default=".", help="Directory containing cloned tool repos")
    parser.add_argument("--tools", nargs="+", help="Specific tools to run (default: all available)")
    parser.add_argument("--category", help="Run only tools in category (cve, ai, api, supply-chain, kubernetes, identity, ransomware, web3, mobile, zero-trust, ai-agent, recon, osint, crypto, exploit-dev, reversing, hardware, wireless, ai-framework)")
    parser.add_argument("--parallel", type=int, default=4, help="Parallel workers")
    parser.add_argument("--timeout", type=int, default=300, help="Per-tool timeout (seconds)")
    parser.add_argument("--output", help="Output file (JSON/SARIF/HTML auto-detected by extension)")
    parser.add_argument("--format", choices=["json", "sarif", "html"], help="Output format (overrides extension)")
    parser.add_argument("--list", action="store_true", help="List available tools and exit")
    parser.add_argument("--list-categories", action="store_true", help="List categories and exit")
    
    # Pass-through args for tools
    parser.add_argument("--target", help="Target for tools (URL, IP, file, contract)")
    parser.add_argument("--api-key", help="API key for LLM/API tools")
    parser.add_argument("--model", default="gpt-3.5-turbo", help="Model for LLM tools")
    parser.add_argument("--auth", help="Auth header for API tools")
    parser.add_argument("--rpc", help="RPC URL for Web3 tools")
    parser.add_argument("--contract", help="Contract address for Web3 tools")
    parser.add_argument("--kubeconfig", default="~/.kube/config", help="Kubeconfig for K8s tools")
    parser.add_argument("--config", help="Config file for Zero Trust tools")
    parser.add_argument("--framework", default="custom", help="Framework for AI agent tools")
    parser.add_argument("--mode", default="all", help="Mode for tools with multiple modes")
    
    args = parser.parse_args()
    
    scanner = SecScan(args.tools_dir)
    discovered = scanner.discover_tools()
    
    if args.list:
        print("Available tools:")
        for name, info in discovered.items():
            status = "✓" if info.get("available") else "✗"
            cat = info.get("category", "?")
            typ = info.get("type", "?")
            print(f"  {status} {name:<35} [{cat}] ({typ})")
        return
    
    if args.list_categories:
        print("Categories:")
        for cat, desc in CATEGORIES.items():
            count = sum(1 for i in discovered.values() if i.get("category") == cat and i.get("available"))
            print(f"  {cat:<20} {desc} ({count} tools)")
        return
    
    # Build config for tools
    tool_args = {}
    for k, v in vars(args).items():
        if v is not None and k not in ["tools_dir", "tools", "category", "parallel", "timeout", "output", "format", "list", "list_categories"]:
            tool_args[k] = v
    
    scanner.config["args"] = tool_args
    scanner.config["timeout"] = args.timeout
    
    # Run scan
    results = scanner.run_scan(
        tool_filter=args.tools,
        category_filter=args.category,
        parallel=args.parallel,
        timeout=args.timeout
    )
    
    # Generate output
    if args.output:
        fmt = args.format
        if not fmt:
            ext = Path(args.output).suffix.lower()
            fmt = {"json": "json", ".sarif": "sarif", ".html": "html"}.get(ext, "json")
        
        if fmt == "sarif":
            scanner.generate_sarif(args.output)
        elif fmt == "html":
            scanner.generate_html(args.output)
        else:
            scanner.generate_json(args.output)
    
    # Print summary
    successful = sum(1 for r in results.values() if r["status"] == "success")
    failed = sum(1 for r in results.values() if r["status"] in ["failed", "error"])
    vuln = sum(1 for r in results.values() if r["status"] == "success" and isinstance(r.get("findings"), dict) and any(v.get("vulnerable") for v in r["findings"].values() if isinstance(v, dict)))
    
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {successful} successful, {failed} failed, {vuln} with findings")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()