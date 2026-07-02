import re


def parse_iac(filename: str, content: str) -> str:
    name = (filename or "config").lower()
    content = content[:20000]

    if content.count("\n") > 2000:
        content = "\n".join(content.splitlines()[:2000])

    if name.endswith(".tf") or name.endswith(".hcl") or 'resource "' in content:
        return _terraform(content)
    if name.endswith((".yaml", ".yml")) and ("kind:" in content or "apiVersion:" in content):
        return _k8s(content)
    if name == "dockerfile" or name.endswith("dockerfile"):
        return _dockerfile(content)
    if "services:" in content and name.endswith((".yml", ".yaml")):
        return _compose(content)

    return f"Infrastructure configuration file '{filename}':\n\n{content}"


def _terraform(content: str) -> str:
    resources = re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', content)
    providers = re.findall(r'provider\s+"([^"]+)"', content)
    lines = ["System infrastructure defined in Terraform.\n"]
    if providers:
        lines.append("Cloud providers: " + ", ".join(sorted(set(providers))) + ".")
    if resources:
        lines.append("Provisioned resources:")
        for rtype, rname in resources[:60]:
            lines.append(f"- {rtype} named '{rname}'")
    j = content.lower()
    hints = []
    if "aws_s3_bucket" in j: hints.append("S3 storage buckets")
    if "aws_db_instance" in j or "rds" in j: hints.append("managed database (RDS)")
    if "aws_iam" in j: hints.append("IAM roles/policies")
    if "security_group" in j: hints.append("network security groups")
    if "aws_lambda" in j: hints.append("serverless functions")
    if "public" in j: hints.append("potentially public-facing resources")
    if hints:
        lines.append("\nSecurity-relevant components: " + ", ".join(hints) + ".")
    return "\n".join(lines)


def _k8s(content: str) -> str:
    kinds = re.findall(r'kind:\s*(\w+)', content)
    images = re.findall(r'image:\s*([^\s]+)', content)
    lines = ["System deployed on Kubernetes.\n"]
    if kinds:
        lines.append("Workload types: " + ", ".join(sorted(set(kinds))) + ".")
    if images:
        lines.append("Container images: " + ", ".join(sorted(set(images))[:20]) + ".")
    j = content.lower()
    hints = []
    if "loadbalancer" in j: hints.append("public LoadBalancer exposure")
    if "secret" in j: hints.append("Kubernetes Secrets in use")
    if "ingress" in j: hints.append("Ingress (external traffic)")
    if "privileged: true" in j: hints.append("privileged containers (high risk)")
    if hints:
        lines.append("\nSecurity-relevant components: " + ", ".join(hints) + ".")
    return "\n".join(lines)


def _dockerfile(content: str) -> str:
    base = re.findall(r'FROM\s+([^\s]+)', content)
    exposed = re.findall(r'EXPOSE\s+(\d+)', content)
    runs_root = "USER" not in content.upper()
    lines = ["Application containerized with Docker.\n"]
    if base:
        lines.append("Base image(s): " + ", ".join(base) + ".")
    if exposed:
        lines.append("Exposed ports: " + ", ".join(exposed) + ".")
    if runs_root:
        lines.append("Container appears to run as root (no USER directive) - elevation risk.")
    return "\n".join(lines)


def _compose(content: str) -> str:
    services = re.findall(r'^\s{2}(\w[\w-]*):', content, re.MULTILINE)
    images = re.findall(r'image:\s*([^\s]+)', content)
    ports = re.findall(r'-\s*"?(\d+):', content)
    lines = ["Multi-service application defined in docker-compose.\n"]
    if services:
        lines.append("Services: " + ", ".join(services[:30]) + ".")
    if images:
        lines.append("Images: " + ", ".join(sorted(set(images))[:20]) + ".")
    if ports:
        lines.append("Exposed host ports: " + ", ".join(sorted(set(ports))) + ".")
    return "\n".join(lines)