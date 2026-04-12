# Finding Chain Builder Agent
# Connect Individual Findings into Attack Chains
# Model findings as a graph, find paths from entry to impact

## Purpose
Take a list of individual security findings and automatically connect them into
exploitable attack chains. Models the attack surface as a directed graph where
nodes are findings and edges are exploitation relationships.

Example: XSS on subdomain A (no CSP) -> CORS on API B (trusts A with creds) -> data theft

## Usage
```
finding-chain-builder <findings.json> [--output chains.json] [--visualize chains.dot]
finding-chain-builder --interactive
finding-chain-builder --from-spray spray_results.json --from-cors cors_results.json
```

## Environment Requirements
- Python 3.10+
- Optional: graphviz (for visualization)

## Finding Input Format

```json
{
  "findings": [
    {
      "id": "f1",
      "type": "xss",
      "subtype": "reflected",
      "target": "blog.target.com",
      "endpoint": "/search?q=PAYLOAD",
      "severity": "medium",
      "details": "Reflected XSS in search parameter",
      "csp_present": false,
      "authenticated": false
    },
    {
      "id": "f2",
      "type": "cors",
      "subtype": "subdomain_wildcard",
      "target": "api.target.com",
      "endpoint": "/v1/user/profile",
      "severity": "high",
      "details": "CORS trusts *.target.com with credentials",
      "credentials": true,
      "trusted_origins": ["*.target.com"]
    },
    {
      "id": "f3",
      "type": "idor",
      "subtype": "direct_reference",
      "target": "api.target.com",
      "endpoint": "/v1/user/{id}/data",
      "severity": "high",
      "details": "Can access other users data by changing ID",
      "authenticated": true
    },
    {
      "id": "f4",
      "type": "missing_header",
      "subtype": "no_csp",
      "target": "blog.target.com",
      "severity": "info",
      "details": "No Content-Security-Policy header"
    },
    {
      "id": "f5",
      "type": "open_redirect",
      "subtype": "parameter_based",
      "target": "auth.target.com",
      "endpoint": "/login?redirect=PAYLOAD",
      "severity": "low",
      "details": "Open redirect after login"
    }
  ]
}
```

## Graph Model

### Node Types (Finding Categories)
```
ENTRY_POINTS (attacker can reach without auth):
  - xss (reflected, stored, DOM)
  - open_redirect
  - csrf
  - ssrf
  - clickjacking
  - phishing (via open redirect)

AMPLIFIERS (increase impact of other findings):
  - cors_misconfiguration
  - missing_csp
  - missing_hsts
  - weak_csrf_protection
  - session_fixation
  - subdomain_takeover

IMPACT_NODES (data theft, account takeover):
  - idor
  - auth_bypass
  - privilege_escalation
  - data_exposure
  - account_takeover
  - rce
```

### Edge Rules (What Chains to What)
```
xss + no_csp -> amplified_xss (XSS is more exploitable without CSP)
xss_on_subdomain + cors_trusts_subdomain -> cross_origin_data_theft
cors_with_creds + sensitive_endpoint -> authenticated_data_theft
open_redirect + oauth_flow -> token_theft
ssrf + cloud_metadata -> credential_theft
idor + session_access -> mass_data_theft
csrf + state_changing_action -> account_manipulation
xss + session_cookie_no_httponly -> session_hijacking
subdomain_takeover + cors_trusts_subdomain -> full_api_access
```

## Full Implementation

```python
#!/usr/bin/env python3
"""
chain_builder.py - Attack Chain Builder
Usage: python3 chain_builder.py findings.json [--output chains.json]
"""

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Tuple, Optional
from itertools import combinations


@dataclass
class Finding:
    id: str
    type: str
    subtype: str = ""
    target: str = ""
    endpoint: str = ""
    severity: str = "info"
    details: str = ""
    csp_present: bool = True
    credentials: bool = False
    authenticated: bool = False
    trusted_origins: List[str] = field(default_factory=list)
    httponly: bool = True
    secure_flag: bool = True

    @property
    def domain(self):
        return self.target.split("/")[0] if self.target else ""

    @property
    def base_domain(self):
        parts = self.domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else self.domain


@dataclass
class Chain:
    id: str
    name: str
    steps: List[Dict]
    impact: str
    cvss_estimate: float
    severity: str
    findings_used: List[str]
    poc_outline: str = ""
    report_template: str = ""


class AttackGraph:
    """Models findings as a directed graph and finds exploitation chains."""

    # Define which finding types are entry points (no auth needed)
    ENTRY_TYPES = {"xss", "open_redirect", "csrf", "clickjacking", "ssrf", "subdomain_takeover"}

    # Define which finding types are impact nodes
    IMPACT_TYPES = {"idor", "auth_bypass", "privilege_escalation", "data_exposure",
                    "account_takeover", "rce", "token_theft"}

    # Chain rules: (condition_function, chain_template)
    CHAIN_RULES = []

    def __init__(self, findings: List[Finding]):
        self.findings = {f.id: f for f in findings}
        self.findings_by_type = defaultdict(list)
        self.findings_by_domain = defaultdict(list)
        self.findings_by_base_domain = defaultdict(list)
        self.adjacency = defaultdict(set)  # finding_id -> set of (finding_id, edge_label)
        self.chains: List[Chain] = []

        for f in findings:
            self.findings_by_type[f.type].append(f)
            self.findings_by_domain[f.domain].append(f)
            self.findings_by_base_domain[f.base_domain].append(f)

    def build_edges(self):
        """Build edges between findings based on chain rules."""
        findings_list = list(self.findings.values())

        for f1, f2 in combinations(findings_list, 2):
            edges = self._check_chainability(f1, f2)
            for edge_label, direction in edges:
                if direction == "forward":
                    self.adjacency[f1.id].add((f2.id, edge_label))
                elif direction == "reverse":
                    self.adjacency[f2.id].add((f1.id, edge_label))
                elif direction == "both":
                    self.adjacency[f1.id].add((f2.id, edge_label))
                    self.adjacency[f2.id].add((f1.id, edge_label))

    def _check_chainability(self, f1: Finding, f2: Finding) -> List[Tuple[str, str]]:
        """Check if two findings can be chained together."""
        edges = []

        # Rule 1: XSS on subdomain + CORS trusting that subdomain
        if f1.type == "xss" and f2.type == "cors":
            if self._subdomain_matches_cors(f1, f2):
                edges.append(("xss_to_cors_chain", "forward"))

        if f2.type == "xss" and f1.type == "cors":
            if self._subdomain_matches_cors(f2, f1):
                edges.append(("xss_to_cors_chain", "reverse"))

        # Rule 2: XSS + missing CSP on same domain (amplification)
        if f1.type == "xss" and f2.type == "missing_header" and f2.subtype == "no_csp":
            if f1.domain == f2.domain or f1.target == f2.target:
                edges.append(("xss_amplified_by_no_csp", "forward"))

        if f2.type == "xss" and f1.type == "missing_header" and f1.subtype == "no_csp":
            if f2.domain == f1.domain or f2.target == f1.target:
                edges.append(("xss_amplified_by_no_csp", "reverse"))

        # Rule 3: CORS with credentials + sensitive API endpoint
        if f1.type == "cors" and f1.credentials and f2.type == "idor":
            if f1.domain == f2.domain or f1.base_domain == f2.base_domain:
                edges.append(("cors_to_idor_data_theft", "forward"))

        if f2.type == "cors" and f2.credentials and f1.type == "idor":
            if f1.domain == f2.domain or f1.base_domain == f2.base_domain:
                edges.append(("cors_to_idor_data_theft", "reverse"))

        # Rule 4: Open redirect + OAuth/SSO flow
        if f1.type == "open_redirect" and f2.type in ("oauth_misconfiguration", "auth_bypass"):
            if f1.base_domain == f2.base_domain:
                edges.append(("redirect_to_token_theft", "forward"))

        # Rule 5: SSRF + cloud metadata
        if f1.type == "ssrf" and f2.type == "data_exposure":
            edges.append(("ssrf_to_data_exposure", "forward"))

        # Rule 6: XSS + cookie without HttpOnly
        if f1.type == "xss" and f2.type == "missing_header" and f2.subtype == "no_httponly":
            if f1.base_domain == f2.base_domain:
                edges.append(("xss_to_session_hijack", "forward"))

        # Rule 7: Subdomain takeover + CORS trusting that subdomain
        if f1.type == "subdomain_takeover" and f2.type == "cors":
            if self._subdomain_matches_cors(f1, f2):
                edges.append(("takeover_to_cors", "forward"))

        # Rule 8: CSRF + state-changing endpoint
        if f1.type == "csrf" and f2.type in ("privilege_escalation", "idor"):
            if f1.base_domain == f2.base_domain:
                edges.append(("csrf_to_state_change", "forward"))

        # Rule 9: Information disclosure + auth bypass
        if f1.type == "info_disclosure" and f2.type in ("auth_bypass", "privilege_escalation"):
            if f1.base_domain == f2.base_domain:
                edges.append(("info_to_auth_bypass", "forward"))

        return edges

    def _subdomain_matches_cors(self, xss_finding: Finding, cors_finding: Finding) -> bool:
        """Check if an XSS finding's domain is trusted by a CORS finding."""
        xss_domain = xss_finding.domain

        for trusted in cors_finding.trusted_origins:
            if trusted == "*.{}".format(cors_finding.base_domain):
                # Wildcard trust - any subdomain of the same base domain matches
                if xss_finding.base_domain == cors_finding.base_domain:
                    return True
            elif trusted == xss_domain:
                return True

        # Also check if CORS subtype indicates subdomain trust
        if cors_finding.subtype == "subdomain_wildcard":
            if xss_finding.base_domain == cors_finding.base_domain:
                return True

        return False

    def find_chains(self) -> List[Chain]:
        """Find all valid attack chains using graph traversal."""
        self.build_edges()
        self.chains = []
        chain_id = 0

        # Strategy 1: Find paths from entry points to impact nodes
        entry_findings = [
            f for f in self.findings.values()
            if f.type in self.ENTRY_TYPES
        ]

        for entry in entry_findings:
            visited = set()
            paths = self._dfs_find_paths(entry.id, visited, [], max_depth=5)
            for path in paths:
                chain_id += 1
                chain = self._build_chain_from_path(f"chain_{chain_id}", path)
                if chain and chain.cvss_estimate > 0:
                    self.chains.append(chain)

        # Strategy 2: Check known chain patterns directly
        pattern_chains = self._check_known_patterns()
        for chain in pattern_chains:
            chain_id += 1
            chain.id = f"chain_{chain_id}"
            if not self._is_duplicate_chain(chain):
                self.chains.append(chain)

        # Sort by CVSS
        self.chains.sort(key=lambda c: c.cvss_estimate, reverse=True)

        # Deduplicate
        seen = set()
        unique_chains = []
        for chain in self.chains:
            key = tuple(sorted(chain.findings_used))
            if key not in seen:
                seen.add(key)
                unique_chains.append(chain)
        self.chains = unique_chains

        return self.chains

    def _dfs_find_paths(self, node_id: str, visited: Set[str],
                        current_path: List[Tuple[str, str]],
                        max_depth: int = 5) -> List[List[Tuple[str, str]]]:
        """DFS to find all paths from current node."""
        if len(current_path) >= max_depth:
            return []

        visited.add(node_id)
        current_path.append((node_id, ""))
        paths = []

        # If current path has >= 2 nodes, it's a potential chain
        if len(current_path) >= 2:
            paths.append(list(current_path))

        for neighbor_id, edge_label in self.adjacency.get(node_id, set()):
            if neighbor_id not in visited:
                current_path[-1] = (node_id, edge_label)
                sub_paths = self._dfs_find_paths(neighbor_id, visited, current_path, max_depth)
                paths.extend(sub_paths)

        current_path.pop()
        visited.discard(node_id)
        return paths

    def _build_chain_from_path(self, chain_id: str, path: List[Tuple[str, str]]) -> Optional[Chain]:
        """Build a Chain object from a graph path."""
        if len(path) < 2:
            return None

        steps = []
        findings_used = []
        for i, (node_id, edge_label) in enumerate(path):
            finding = self.findings[node_id]
            findings_used.append(node_id)
            step = {
                "step": i + 1,
                "finding_id": node_id,
                "type": finding.type,
                "target": finding.target,
                "action": self._describe_step(finding, edge_label, i == 0),
                "edge_to_next": edge_label if edge_label else None,
            }
            steps.append(step)

        # Determine impact
        last_finding = self.findings[path[-1][0]]
        impact = self._determine_impact(steps, [self.findings[fid] for fid, _ in path])
        cvss = self._estimate_cvss(steps, [self.findings[fid] for fid, _ in path])
        severity = (
            "critical" if cvss >= 9.0 else
            "high" if cvss >= 7.0 else
            "medium" if cvss >= 4.0 else
            "low"
        )

        chain = Chain(
            id=chain_id,
            name=self._generate_chain_name(steps),
            steps=steps,
            impact=impact,
            cvss_estimate=cvss,
            severity=severity,
            findings_used=findings_used,
            poc_outline=self._generate_poc_outline(steps),
            report_template=self._generate_report(steps, impact, cvss),
        )
        return chain

    def _describe_step(self, finding: Finding, edge_label: str, is_entry: bool) -> str:
        """Generate human-readable description of a chain step."""
        descriptions = {
            "xss": f"Execute JavaScript on {finding.target} via {finding.subtype} XSS at {finding.endpoint}",
            "cors": f"Exploit CORS misconfiguration on {finding.target} ({finding.subtype})",
            "idor": f"Access unauthorized data via IDOR at {finding.endpoint}",
            "open_redirect": f"Redirect victim from {finding.target} via {finding.endpoint}",
            "csrf": f"Forge cross-site request to {finding.target}{finding.endpoint}",
            "ssrf": f"Make server-side request from {finding.target}",
            "missing_header": f"Leverage missing {finding.subtype} on {finding.target}",
            "subdomain_takeover": f"Control subdomain {finding.target}",
            "auth_bypass": f"Bypass authentication on {finding.target}",
            "data_exposure": f"Access exposed data at {finding.target}{finding.endpoint}",
        }
        return descriptions.get(finding.type, f"Exploit {finding.type} on {finding.target}")

    def _determine_impact(self, steps: List[Dict], findings: List[Finding]) -> str:
        """Determine the overall impact of a chain."""
        types = {f.type for f in findings}
        has_creds_cors = any(f.credentials for f in findings if f.type == "cors")

        if "rce" in types:
            return "Remote Code Execution - Full server compromise"
        if has_creds_cors and "xss" in types:
            return "Authenticated data theft via XSS->CORS chain - read victim's private data"
        if "idor" in types and has_creds_cors:
            return "Mass data theft - access any user's data via CORS+IDOR chain"
        if "auth_bypass" in types:
            return "Authentication bypass - access protected resources"
        if "xss" in types and any(not f.httponly for f in findings):
            return "Session hijacking via XSS - steal session cookies"
        if "open_redirect" in types:
            return "Token theft via OAuth redirect manipulation"
        if "xss" in types:
            return "Cross-site scripting with potential for session/data theft"
        return "Chained vulnerability with escalated impact"

    def _estimate_cvss(self, steps: List[Dict], findings: List[Finding]) -> float:
        """Estimate CVSS score for the chain."""
        types = {f.type for f in findings}
        has_creds_cors = any(f.credentials for f in findings if f.type == "cors")
        has_no_csp = any(f.subtype == "no_csp" for f in findings)

        # XSS + CORS with credentials = 8.1+
        if "xss" in types and "cors" in types and has_creds_cors:
            return 8.7 if has_no_csp else 8.1

        # Subdomain takeover + CORS = 9.0+
        if "subdomain_takeover" in types and "cors" in types and has_creds_cors:
            return 9.1

        # SSRF to cloud metadata
        if "ssrf" in types and "data_exposure" in types:
            return 8.5

        # XSS + no CSP + session theft
        if "xss" in types and has_no_csp:
            return 7.5

        # CORS with credentials alone
        if "cors" in types and has_creds_cors:
            return 7.0

        # Open redirect + OAuth
        if "open_redirect" in types and "auth_bypass" in types:
            return 7.5

        # Default: sum individual severities with chain bonus
        severity_scores = {"critical": 9, "high": 7, "medium": 4, "low": 2, "info": 0}
        base = max(severity_scores.get(f.severity, 0) for f in findings)
        chain_bonus = min(len(steps) * 0.5, 2.0)
        return min(base + chain_bonus, 10.0)

    def _generate_chain_name(self, steps: List[Dict]) -> str:
        """Generate a descriptive chain name."""
        types = [s["type"] for s in steps]
        type_str = " -> ".join(types)
        return f"Chain: {type_str}"

    def _generate_poc_outline(self, steps: List[Dict]) -> str:
        """Generate proof-of-concept outline for the chain."""
        lines = ["# Attack Chain Proof of Concept\n"]
        for step in steps:
            lines.append(f"## Step {step['step']}: {step['action']}")
            lines.append(f"Target: {step['target']}")
            if step.get("edge_to_next"):
                lines.append(f"Chain link: {step['edge_to_next']}")
            lines.append("")
        return "\n".join(lines)

    def _generate_report(self, steps: List[Dict], impact: str, cvss: float) -> str:
        """Generate a draft bug bounty report for the chain."""
        severity = (
            "Critical" if cvss >= 9.0 else
            "High" if cvss >= 7.0 else
            "Medium" if cvss >= 4.0 else
            "Low"
        )
        step_descriptions = "\n".join(
            f"{s['step']}. {s['action']}" for s in steps
        )
        return f"""## Title
Chained Vulnerability: {' + '.join(set(s['type'] for s in steps))} leading to {impact.split(' - ')[0]}

## Severity
{severity} (CVSS {cvss})

## Summary
A chain of {len(steps)} vulnerabilities can be combined to achieve: {impact}

## Steps to Reproduce
{step_descriptions}

## Impact
{impact}

An attacker can exploit this chain without any special access. The attack requires
the victim to visit an attacker-controlled page while authenticated to the target.

## Remediation
{"- ".join(f"Fix {s['type']} on {s['target']}" + chr(10) for s in steps)}
"""

    def _check_known_patterns(self) -> List[Chain]:
        """Check for well-known chain patterns."""
        chains = []

        # Pattern: XSS on subdomain + no CSP + CORS on API trusting subdomain
        xss_findings = self.findings_by_type.get("xss", [])
        cors_findings = self.findings_by_type.get("cors", [])
        no_csp = [f for f in self.findings_by_type.get("missing_header", []) if f.subtype == "no_csp"]

        for xss in xss_findings:
            for cors in cors_findings:
                if cors.credentials and self._subdomain_matches_cors(xss, cors):
                    # Check if XSS domain has no CSP
                    xss_has_no_csp = any(c.domain == xss.domain for c in no_csp)
                    steps = [
                        {"step": 1, "finding_id": xss.id, "type": "xss",
                         "target": xss.target,
                         "action": f"XSS on {xss.target} {'(no CSP)' if xss_has_no_csp else ''}",
                         "edge_to_next": "xss_to_cors_chain"},
                        {"step": 2, "finding_id": cors.id, "type": "cors",
                         "target": cors.target,
                         "action": f"CORS on {cors.target} trusts {xss.domain} with credentials",
                         "edge_to_next": None},
                    ]
                    findings_used = [xss.id, cors.id]
                    if xss_has_no_csp:
                        csp_finding = next(c for c in no_csp if c.domain == xss.domain)
                        findings_used.append(csp_finding.id)

                    chains.append(Chain(
                        id="",
                        name=f"XSS->CORS Data Theft ({xss.domain} -> {cors.target})",
                        steps=steps,
                        impact="Authenticated data theft - read victim's private API data",
                        cvss_estimate=8.7 if xss_has_no_csp else 8.1,
                        severity="critical",
                        findings_used=findings_used,
                        poc_outline=self._generate_poc_outline(steps),
                        report_template="",
                    ))

        return chains

    def _is_duplicate_chain(self, new_chain: Chain) -> bool:
        """Check if a chain is a duplicate of an existing one."""
        new_key = tuple(sorted(new_chain.findings_used))
        for existing in self.chains:
            if tuple(sorted(existing.findings_used)) == new_key:
                return True
        return False

    def export_dot(self, filename: str):
        """Export graph to DOT format for visualization."""
        lines = ["digraph AttackChains {", "  rankdir=LR;", "  node [shape=box];"]

        # Color nodes by type
        colors = {
            "xss": "red", "cors": "orange", "idor": "yellow",
            "open_redirect": "pink", "missing_header": "lightblue",
            "ssrf": "red", "subdomain_takeover": "darkred",
        }

        for fid, finding in self.findings.items():
            color = colors.get(finding.type, "white")
            label = f"{finding.type}\\n{finding.target}"
            lines.append(f'  "{fid}" [label="{label}" fillcolor="{color}" style="filled"];')

        for src, edges in self.adjacency.items():
            for dst, label in edges:
                lines.append(f'  "{src}" -> "{dst}" [label="{label}"];')

        lines.append("}")

        with open(filename, "w") as f:
            f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Attack Chain Builder")
    parser.add_argument("findings", nargs="?", help="JSON file with findings")
    parser.add_argument("--output", help="Output chains JSON file")
    parser.add_argument("--visualize", help="Output DOT file for graphviz")
    parser.add_argument("--from-spray", help="Import from spray-scanner results")
    parser.add_argument("--from-cors", help="Import from cors-chain results")
    parser.add_argument("--min-cvss", type=float, default=0, help="Minimum CVSS to display")
    args = parser.parse_args()

    findings = []

    # Load findings from main input
    if args.findings:
        with open(args.findings) as f:
            data = json.load(f)
        for f_data in data.get("findings", data if isinstance(data, list) else []):
            findings.append(Finding(**{k: v for k, v in f_data.items() if k in Finding.__dataclass_fields__}))

    # Import from spray-scanner
    if args.from_spray:
        with open(args.from_spray) as f:
            spray_data = json.load(f)
        for i, result in enumerate(spray_data.get("results", [])):
            for j, finding in enumerate(result.get("findings", [])):
                findings.append(Finding(
                    id=f"spray_{i}_{j}",
                    type=finding.get("category", "unknown"),
                    subtype=finding.get("title", "").lower().replace(" ", "_"),
                    target=result.get("target", ""),
                    severity=finding.get("severity", "info"),
                    details=finding.get("detail", ""),
                ))

    # Import from cors-chain
    if args.from_cors:
        with open(args.from_cors) as f:
            cors_data = json.load(f)
        cors_results = cors_data if isinstance(cors_data, list) else [cors_data]
        for i, result in enumerate(cors_results):
            for j, step in enumerate(result.get("results", [])):
                if step.get("vulnerable"):
                    findings.append(Finding(
                        id=f"cors_{i}_{j}",
                        type="cors",
                        subtype=step.get("name", ""),
                        target=result.get("target", ""),
                        severity=step.get("severity", "info"),
                        details=step.get("notes", ""),
                        credentials=step.get("acac_received", "").lower() == "true",
                    ))

    if not findings:
        print("[!] No findings to analyze. Provide a findings JSON file.")
        parser.print_help()
        return

    print(f"\n{'='*60}")
    print(f"  Attack Chain Builder")
    print(f"  Analyzing {len(findings)} findings")
    print(f"{'='*60}\n")

    graph = AttackGraph(findings)
    chains = graph.find_chains()

    # Filter by CVSS
    if args.min_cvss > 0:
        chains = [c for c in chains if c.cvss_estimate >= args.min_cvss]

    # Display chains
    if chains:
        print(f"  Found {len(chains)} attack chains:\n")
        for chain in chains:
            color = "\033[91m" if chain.severity == "critical" else "\033[93m" if chain.severity == "high" else ""
            reset = "\033[0m" if color else ""
            print(f"  {color}[{chain.severity.upper()} | CVSS {chain.cvss_estimate}] {chain.name}{reset}")
            for step in chain.steps:
                arrow = "->" if step.get("edge_to_next") else "**"
                print(f"    {step['step']}. {step['action']}")
            print(f"    Impact: {chain.impact}")
            print()
    else:
        print("  No attack chains found.")
        print("  Tips: Look for XSS+CORS, SSRF+metadata, redirect+OAuth combinations")

    # Save output
    if args.output:
        output = {
            "findings_count": len(findings),
            "chains_count": len(chains),
            "chains": [asdict(c) for c in chains],
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[+] Chains saved to {args.output}")

    # Generate visualization
    if args.visualize:
        graph.export_dot(args.visualize)
        print(f"[+] Graph exported to {args.visualize}")
        print(f"    Render with: dot -Tpng {args.visualize} -o chains.png")


if __name__ == "__main__":
    main()
```

## Quick Commands

### From individual finding files
```bash
python3 chain_builder.py findings.json --output chains.json --visualize chains.dot
```

### From spray-scanner + cors-chain output
```bash
python3 chain_builder.py --from-spray ../spray-scanner/results.json --from-cors ../cors-chain/cors_finding.json --output chains.json
```

### Render visualization
```bash
dot -Tpng chains.dot -o chains.png && open chains.png
```

### Filter high-impact chains only
```bash
python3 chain_builder.py findings.json --min-cvss 7.0 --output high_impact_chains.json
```

## Integration Pipeline

### Full chain: recon -> scan -> chain
```bash
# 1. Passive recon
python3 ../ghost-recon/ghost_recon.py target.com --output-dir ./recon

# 2. Spray scan subdomains
python3 ../spray-scanner/spray_scanner.py ./recon/target.com_subdomains.txt --output spray.json

# 3. CORS test high-value targets
jq -r '.results[] | select(.score > 20) | .target' spray.json | while read t; do
  python3 ../cors-chain/cors_chain.py "$t" --output "cors_$(echo $t | md5sum | cut -c1-8).json"
done
cat cors_*.json | jq -s '.' > all_cors.json

# 4. Build chains
python3 chain_builder.py --from-spray spray.json --from-cors all_cors.json --output chains.json
```
