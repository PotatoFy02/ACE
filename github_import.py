import os
import re
import requests

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
ALLOWED_EXT = (".tf", ".hcl", ".yaml", ".yml", ".json")
MAX_FILES = 25
MAX_TOTAL_BYTES = 7000
MAX_SINGLE_FILE = 60000
TIMEOUT = 10

REPO_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


class GitHubImportError(Exception):
    pass


def _headers():
    h = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def _check_rate_limit(r):
    if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
        raise GitHubImportError(
            "GitHub API rate limit hit. Try again later." if GITHUB_TOKEN
            else "GitHub API rate limit hit (unauthenticated). Set GITHUB_TOKEN to raise the limit."
        )


def parse_repo_url(url: str):
    url = url.strip()
    m = REPO_URL_RE.match(url)
    if not m:
        raise GitHubImportError("Invalid GitHub repo URL. Use https://github.com/owner/repo")
    return m.group(1), m.group(2)


def _get_default_branch(owner: str, repo: str) -> str:
    r = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=_headers(), timeout=TIMEOUT)
    _check_rate_limit(r)
    if r.status_code == 404:
        raise GitHubImportError("Repository not found or is private.")
    if r.status_code != 200:
        raise GitHubImportError("Could not access repository.")
    return r.json().get("default_branch", "main")


def _list_tree(owner: str, repo: str, branch: str):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    r = requests.get(url, headers=_headers(), timeout=TIMEOUT)
    _check_rate_limit(r)
    if r.status_code != 200:
        raise GitHubImportError("Could not read repository file tree.")
    return r.json().get("tree", [])


def _is_iac_file(path: str) -> bool:
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1]
    if name == "dockerfile" or name.endswith("dockerfile"):
        return True
    return any(lower.endswith(e) for e in ALLOWED_EXT)


def fetch_iac_from_repo(url: str, parse_fn) -> str:
    owner, repo = parse_repo_url(url)
    branch = _get_default_branch(owner, repo)
    tree = _list_tree(owner, repo, branch)

    iac_paths = [
        node["path"] for node in tree
        if node.get("type") == "blob" and _is_iac_file(node["path"])
    ][:MAX_FILES]

    if not iac_paths:
        raise GitHubImportError(
            "No Infrastructure-as-Code files found (.tf, .yaml, .yml, .json, Dockerfile)."
        )

    summaries = []
    total = 0
    for path in iac_paths:
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        fr = requests.get(raw_url, timeout=TIMEOUT)
        if fr.status_code != 200:
            continue
        content = fr.content
        if len(content) > MAX_SINGLE_FILE:
            content = content[:MAX_SINGLE_FILE]
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        text = "".join(ch for ch in text if ch in ("\n", "\t") or ord(ch) >= 32)
        filename = path.rsplit("/", 1)[-1]
        summary = parse_fn(filename, text)
        block = f"### {path}\n{summary}\n"
        if total + len(block) > MAX_TOTAL_BYTES:
            break
        summaries.append(block)
        total += len(block)

    if not summaries:
        raise GitHubImportError("Could not download any readable IaC files.")

    header = f"Repository '{owner}/{repo}' contains the following infrastructure:\n\n"
    return header + "\n".join(summaries)