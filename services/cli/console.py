"""SCARABEO CLI console interface."""

import sys
from typing import Any

from scarabeo.banner import show_banner
from scarabeo.version import get_version
from services.cli.client import ScarabeoClient, APIError


# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


class Console:
    """Interactive console for SCARABEO."""

    def __init__(self, client: ScarabeoClient | None = None):
        """
        Initialize console.

        Args:
            client: API client (creates default if None)
        """
        self.client = client or ScarabeoClient()
        self.running = True
        self.prompt = "scarabeo > "

    def print(self, message: str = "") -> None:
        """Print message to stdout."""
        print(message)

    def print_error(self, message: str) -> None:
        """Print error message."""
        print(f"ERROR: {message}", file=sys.stderr)

    def print_success(self, message: str) -> None:
        """Print success message."""
        print(f"OK: {message}")

    def print_json(self, data: Any, indent: int = 2) -> None:
        """Print JSON data."""
        import json
        print(json.dumps(data, indent=indent, default=str))

    def show_help(self) -> None:
        """Show help message."""
        help_text = """
SCARABEO CLI Commands:
  help                    Show this help message
  version                 Show version information
  upload <file>           Upload a sample file for analysis
  status <sha256>         Get sample status by SHA256 hash
  report <sha256>         Get analysis report by SHA256 hash
  jobs                    List recent jobs
  search <query>          Search samples
  cases                   List cases
  case-create <name>      Create a new case
  case-add <case_id> <sha256>  Add sample to case
  intel <ioc>             Get IOC intelligence
  verdict <sha256> <verdict> [reason...]  Set sample verdict
  tag-add <sha256> <tag>  Add tag to sample
  tags <sha256>           Get sample tags
  note <sha256> <text...> Add note to sample
  export <sha256> <out.zip>  Export sample data
  clusters                List similarity clusters
  cluster <id>            Get cluster details
  sample-clusters <sha256>  Get clusters for sample
  exit                    Exit the console

Environment Variables:
  SCARABEO_API_URL        API base URL (default: http://localhost:8000)
  SCARABEO_TENANT         Tenant ID (default: default)
  SCARABEO_USER           User ID (default: cli-user)
  SCARABEO_ROLE           User role (default: analyst)

Examples:
  scarabeo > upload malware.exe
  scarabeo > status a1b2c3d4e5f6...
  scarabeo > report a1b2c3d4e5f6...
  scarabeo > jobs
  scarabeo > search verdict:malicious
  scarabeo > search type:pe tag:ransomware
  scarabeo > cases
  scarabeo > case-create "APT Campaign"
  scarabeo > case-add <case_id> <sha256>
  scarabeo > intel evil.com
  scarabeo > verdict a1b2c3... malicious Ransomware detected
  scarabeo > tag-add a1b2c3... ransomware
  scarabeo > tags a1b2c3...
  scarabeo > note a1b2c3... Suspicious network activity observed
  scarabeo > export a1b2c3... sample_export.zip
  scarabeo > clusters
  scarabeo > cluster 550e8400-e29b-41d4-a716-446655440000
  scarabeo > sample-clusters a1b2c3d4e5f6...
"""
        self.print(help_text)

    def show_version(self) -> None:
        """Show version information."""
        version = get_version()
        self.print(f"SCARABEO Analysis Framework v{version}")

    def cmd_upload(self, args: list[str]) -> None:
        """Handle upload command."""
        if not args:
            self.print_error("Usage: upload <file>")
            return

        file_path = args[0]
        priority = args[1] if len(args) > 1 else "normal"

        try:
            result = self.client.upload_sample(file_path, priority)
            self.print_success(f"Sample uploaded")
            self.print(f"  SHA256: {result.get('sha256', 'N/A')}")
            self.print(f"  Submission ID: {result.get('submission_id', 'N/A')}")
            self.print(f"  Status: {result.get('status', 'N/A')}")
        except FileNotFoundError:
            self.print_error(f"File not found: {file_path}")
        except (ConnectionError, APIError) as e:
            self.print_error(str(e))

    def cmd_status(self, args: list[str]) -> None:
        """Handle status command."""
        if not args:
            self.print_error("Usage: status <sha256>")
            return

        sha256 = args[0]

        try:
            sample = self.client.get_sample(sha256)
            self.print_json(sample)
        except (ConnectionError, APIError) as e:
            self.print_error(str(e))

    def cmd_report(self, args: list[str]) -> None:
        """Handle report command."""
        if not args:
            self.print_error("Usage: report <sha256>")
            return

        sha256 = args[0]

        try:
            report = self.client.get_report(sha256)
            self.print_json(report)
        except (ConnectionError, APIError) as e:
            self.print_error(str(e))

    def cmd_jobs(self, args: list[str]) -> None:
        """Handle jobs command."""
        status = args[0] if args else None

        try:
            jobs = self.client.list_jobs(status)
            if not jobs:
                self.print("No jobs found")
                return

            self.print(f"{'ID':<40} {'Status':<12} {'Pipeline':<15} {'Created':<25}")
            self.print("-" * 95)
            for job in jobs[:20]:
                job_id = job.get('id', 'N/A')[:36] + "..." if len(job.get('id', '')) > 36 else job.get('id', 'N/A')
                status = job.get('status', 'N/A')
                pipeline = job.get('pipeline_name', 'N/A')
                created = job.get('created_at', 'N/A')[:19]
                self.print(f"{job_id:<40} {status:<12} {pipeline:<15} {created:<25}")
        except (ConnectionError, APIError) as e:
            self.print_error(str(e))

    def cmd_search(self, args: list[str]) -> None:
        """Handle search command."""
        if not args:
            self.print_error("Usage: search <query>")
            self.print("Examples: search verdict:malicious, search type:pe tag:ransomware")
            return

        query = " ".join(args)

        try:
            # Use search endpoint via direct API call
            import requests
            url = f"{self.client.base_url}/search"
            params = {"q": query}
            headers = dict(self.client.session.headers)
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()

            items = result.get("items", [])
            total = result.get("total", 0)

            self.print(f"Found {total} results")
            self.print()

            if items:
                self.print(f"{'SHA256':<64} {'Type':<12} {'Verdict':<12} {'Score':<6}")
                self.print("-" * 98)
                for item in items:
                    sha = item.get('sample_sha256', 'N/A')
                    ftype = item.get('file_type', 'N/A')[:12]
                    verdict = item.get('verdict', 'N/A')[:12]
                    score = str(item.get('score', 'N/A'))[:6]
                    self.print(f"{sha:<64} {ftype:<12} {verdict:<12} {score:<6}")
        except (ConnectionError, APIError, requests.RequestException) as e:
            self.print_error(str(e))

    def cmd_cases(self, args: list[str]) -> None:
        """Handle cases command."""
        try:
            import requests
            url = f"{self.client.base_url}/cases"
            headers = dict(self.client.session.headers)
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            cases = response.json()

            if not cases:
                self.print("No cases found")
                return

            self.print(f"{'ID':<40} {'Name':<25} {'Samples':<10} {'Created':<25}")
            self.print("-" * 105)
            for case in cases[:20]:
                case_id = case.get('id', 'N/A')[:36] + "..." if len(case.get('id', '')) > 36 else case.get('id', 'N/A')
                name = case.get('name', 'N/A')[:25]
                samples = str(case.get('sample_count', 0))[:10]
                created = case.get('created_at', 'N/A')[:25]
                self.print(f"{case_id:<40} {name:<25} {samples:<10} {created:<25}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_case_create(self, args: list[str]) -> None:
        """Handle case-create command."""
        if not args:
            self.print_error("Usage: case-create <name>")
            return

        name = args[0]
        description = " ".join(args[1:]) if len(args) > 1 else None

        try:
            import requests
            import json
            url = f"{self.client.base_url}/cases"
            headers = dict(self.client.session.headers)
            headers["Content-Type"] = "application/json"
            
            data = {"name": name}
            if description:
                data["description"] = description

            response = requests.post(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()
            case = response.json()

            self.print_success(f"Case created")
            self.print(f"  ID: {case.get('id', 'N/A')}")
            self.print(f"  Name: {case.get('name', 'N/A')}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_case_add(self, args: list[str]) -> None:
        """Handle case-add command."""
        if len(args) < 2:
            self.print_error("Usage: case-add <case_id> <sha256>")
            return

        case_id = args[0]
        sha256 = args[1]
        notes = " ".join(args[2:]) if len(args) > 2 else None

        try:
            import requests
            import json
            url = f"{self.client.base_url}/cases/{case_id}/samples"
            headers = dict(self.client.session.headers)
            headers["Content-Type"] = "application/json"
            
            data = {"sample_sha256": sha256}
            if notes:
                data["notes"] = notes

            response = requests.post(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()

            self.print_success(f"Sample added to case {case_id}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_intel(self, args: list[str]) -> None:
        """Handle intel command."""
        if not args:
            self.print_error("Usage: intel <ioc_value>")
            return

        ioc_value = args[0]

        try:
            import requests
            url = f"{self.client.base_url}/intel/ioc/{ioc_value}"
            headers = dict(self.client.session.headers)
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 404:
                self.print(f"IOC not found: {ioc_value}")
                return

            response.raise_for_status()
            intel = response.json()

            self.print(f"IOC Intelligence: {ioc_value}")
            self.print(f"  Type: {intel.get('ioc_type', 'N/A')}")
            self.print(f"  Total Sightings: {intel.get('total_sightings', 'N/A')}")
            self.print(f"  Samples: {intel.get('sample_count', 'N/A')}")
            self.print(f"  First Seen: {intel.get('first_seen', 'N/A')}")
            self.print(f"  Last Seen: {intel.get('last_seen', 'N/A')}")
            self.print(f"  Tenants: {', '.join(intel.get('tenants', []))}")

            samples = intel.get('samples', [])[:10]
            if samples:
                self.print()
                self.print("  Sample SHA256s:")
                for sha in samples:
                    self.print(f"    - {sha[:32]}...")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_verdict(self, args: list[str]) -> None:
        """Handle verdict command."""
        if len(args) < 2:
            self.print_error("Usage: verdict <sha256> <verdict> [reason...]")
            self.print("Verdicts: unknown, benign, suspicious, malicious")
            return

        sha256 = args[0]
        verdict = args[1]
        reason = " ".join(args[2:]) if len(args) > 2 else None

        try:
            import requests
            import json
            url = f"{self.client.base_url}/samples/{sha256}/verdict"
            headers = dict(self.client.session.headers)
            headers["Content-Type"] = "application/json"

            data = {"verdict": verdict}
            if reason:
                data["reason"] = reason

            response = requests.post(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()

            self.print_success(f"Verdict set: {result.get('verdict')}")
            if result.get('reason'):
                self.print(f"  Reason: {result['reason']}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_tag_add(self, args: list[str]) -> None:
        """Handle tag-add command."""
        if len(args) < 2:
            self.print_error("Usage: tag-add <sha256> <tag>")
            return

        sha256 = args[0]
        tag = args[1]

        try:
            import requests
            url = f"{self.client.base_url}/samples/{sha256}/tags"
            headers = dict(self.client.session.headers)
            headers["Content-Type"] = "application/json"

            response = requests.post(url, json={"tag": tag}, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()

            self.print_success(f"Tags: {', '.join(result.get('tags', []))}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_tags(self, args: list[str]) -> None:
        """Handle tags command."""
        if not args:
            self.print_error("Usage: tags <sha256>")
            return

        sha256 = args[0]

        try:
            import requests
            url = f"{self.client.base_url}/samples/{sha256}/tags"
            headers = dict(self.client.session.headers)

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()

            tags = result.get('tags', [])
            if tags:
                self.print(f"Tags for {sha256[:16]}...: {', '.join(tags)}")
            else:
                self.print("No tags")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_note(self, args: list[str]) -> None:
        """Handle note command."""
        if len(args) < 2:
            self.print_error("Usage: note <sha256> <text...>")
            return

        sha256 = args[0]
        body = " ".join(args[1:])

        try:
            import requests
            url = f"{self.client.base_url}/samples/{sha256}/notes"
            headers = dict(self.client.session.headers)
            headers["Content-Type"] = "application/json"

            response = requests.post(url, json={"body": body}, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()

            self.print_success(f"Note added by {result.get('author_id')}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_export(self, args: list[str]) -> None:
        """Handle export command."""
        if len(args) < 2:
            self.print_error("Usage: export <sha256> <output.zip>")
            return

        sha256 = args[0]
        output_path = args[1]

        try:
            import requests
            url = f"{self.client.base_url}/samples/{sha256}/export"
            headers = dict(self.client.session.headers)

            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()

            with open(output_path, "wb") as f:
                f.write(response.content)

            self.print_success(f"Export saved to {output_path}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_clusters(self, args: list[str]) -> None:
        """Handle clusters command."""
        try:
            import requests
            url = f"{self.client.base_url}/clusters"
            headers = dict(self.client.session.headers)

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            clusters = response.json()

            if not clusters:
                self.print("No clusters found")
                return

            self.print(f"{'ID':<40} {'Algorithm':<15} {'Members':<10} {'Created':<25}")
            self.print("-" * 95)
            for cluster in clusters[:20]:
                cid = cluster.get('cluster_id', 'N/A')[:36] + "..." if len(cluster.get('cluster_id', '')) > 36 else cluster.get('cluster_id', 'N/A')
                algo = cluster.get('algorithm', 'N/A')[:15]
                members = str(cluster.get('member_count', 0))[:10]
                created = cluster.get('created_at', 'N/A')[:25]
                self.print(f"{cid:<40} {algo:<15} {members:<10} {created:<25}")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_cluster(self, args: list[str]) -> None:
        """Handle cluster command."""
        if not args:
            self.print_error("Usage: cluster <id>")
            return

        cluster_id = args[0]

        try:
            import requests
            url = f"{self.client.base_url}/clusters/{cluster_id}"
            headers = dict(self.client.session.headers)

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            cluster = response.json()

            self.print(f"Cluster: {cluster.get('cluster_id', 'N/A')}")
            self.print(f"  Algorithm: {cluster.get('algorithm', 'N/A')}")
            self.print(f"  Threshold: {cluster.get('threshold', 'N/A')}")
            self.print(f"  Primary Sample: {cluster.get('primary_sample_sha256', 'N/A')[:32]}...")
            self.print(f"  Created: {cluster.get('created_at', 'N/A')}")
            self.print(f"  Members: {len(cluster.get('members', []))}")

            members = cluster.get('members', [])[:10]
            if members:
                self.print()
                self.print("  Recent Members:")
                for m in members:
                    self.print(f"    - {m.get('sample_sha256', 'N/A')[:32]}... (score: {m.get('score', 0)})")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def cmd_sample_clusters(self, args: list[str]) -> None:
        """Handle sample-clusters command."""
        if not args:
            self.print_error("Usage: sample-clusters <sha256>")
            return

        sha256 = args[0]

        try:
            import requests
            url = f"{self.client.base_url}/clusters/samples/{sha256}/clusters"
            headers = dict(self.client.session.headers)

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()

            clusters = result.get('clusters', [])
            if not clusters:
                self.print(f"No clusters found for sample {sha256[:16]}...")
                return

            self.print(f"Sample {sha256[:16]}... is in {len(clusters)} clusters:")
            for c in clusters:
                self.print(f"  - {c.get('cluster_id', 'N/A')[:36]}... ({c.get('algorithm', 'N/A')}, score: {c.get('score', 0)})")
        except (ConnectionError, APIError, Exception) as e:
            self.print_error(str(e))

    def process_command(self, line: str) -> bool:
        """
        Process a command line.

        Args:
            line: Command line input

        Returns:
            True to continue, False to exit
        """
        line = line.strip()
        if not line:
            return True

        parts = line.split()
        command = parts[0].lower()
        args = parts[1:]

        if command == "exit" or command == "quit":
            self.running = False
            return False
        elif command == "help" or command == "?":
            self.show_help()
        elif command == "version":
            self.show_version()
        elif command == "upload":
            self.cmd_upload(args)
        elif command == "status":
            self.cmd_status(args)
        elif command == "report":
            self.cmd_report(args)
        elif command == "jobs":
            self.cmd_jobs(args)
        elif command == "search":
            self.cmd_search(args)
        elif command == "cases":
            self.cmd_cases(args)
        elif command == "case-create":
            self.cmd_case_create(args)
        elif command == "case-add":
            self.cmd_case_add(args)
        elif command == "intel":
            self.cmd_intel(args)
        elif command == "verdict":
            self.cmd_verdict(args)
        elif command == "tag-add":
            self.cmd_tag_add(args)
        elif command == "tags":
            self.cmd_tags(args)
        elif command == "note":
            self.cmd_note(args)
        elif command == "export":
            self.cmd_export(args)
        elif command == "clusters":
            self.cmd_clusters(args)
        elif command == "cluster":
            self.cmd_cluster(args)
        elif command == "sample-clusters":
            self.cmd_sample_clusters(args)
        else:
            self.print_error(f"Unknown command: {command}")
            self.print("Type 'help' for available commands")

        return True

    def run(self) -> None:
        """Run the interactive console."""
        # Show banner once at startup
        show_banner()

        self.print(f"Connected to: {self.client.base_url}")
        self.print(f"Tenant: {self.client.tenant_id}")
        self.print(f"Type 'help' for available commands")
        self.print()

        while self.running:
            try:
                line = input(self.prompt)
                self.process_command(line)
            except EOFError:
                self.print()
                self.print("Goodbye!")
                break
            except KeyboardInterrupt:
                self.print()
                continue


def main() -> None:
    """Main entry point for CLI."""
    console = Console()
    console.run()


if __name__ == "__main__":
    main()
