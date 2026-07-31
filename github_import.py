import os
import re
import logging
import requests

log = logging.getLogger("github_import")

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
ALLOWED_EXT = (".tf", ".hcl", ".yaml", ".yml", ".json")
MAX_FILES = 25
MAX_CHARS = 12000
MAX_SINGLE_FILE = 60000
TIMEOUT = 10
MIN_QUOTA_REMAINING = 5

RISKY_SCOPES = {"repo", "admin:org", "delete_repo", "admin:repo_hook", "workflow"}

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


def verify_pat_scope() -> None:
    if not GITHUB_TOKEN:
        log.warning(
            "GITHUB_TOKEN not set - running unauthenticated (60 req/hr, "
            "shared across ALL users of this app)."
        )
        return
    try:
        r = requests.get(f"{GITHUB_API}/rate_limit", headers=_headers(), timeout=TIMEOUT)
    except requests.RequestException as e:
        log.warning("Could not verify GITHUB_TOKEN scope at startup: %r", e)
        return
    scopes_header = r.headers.get("X-OAuth-Scopes", "")
    granted = {s.strip() for s in scopes_header.split(",") if s.strip()}
    if not scopes_header:
        log.info(
            "GITHUB_TOKEN has no classic OAuth scopes (likely a fine-grained "
            "PAT, or a token with zero scopes). This is the minimal footprint "
            "ACE needs for reading public repos."
        )
    elif granted & RISKY_SCOPES:
        log.warning(
            "GITHUB_TOKEN scope is broader than ACE needs: %s. ACE only reads "
            "public repo file trees/contents - re-issue as a fine-grained PAT "
            "scoped to 'Public Repositories (read-only)' to shrink blast radius.",
            sorted(granted & RISKY_SCOPES),
        )
    else:
        log.info("GITHUB_TOKEN scopes: %s", sorted(granted))


def _check_rate_limit(r):
    if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
        raise GitHubImportError(
            "GitHub API rate limit hit. Try again later." if GITHUB_TOKEN
            else "GitHub API rate limit hit (unauthenticated). Set GITHUB_TOKEN to raise the limit."
        )


def _check_quota_before_fetch():
    try:
        r = requests.get(f"{GITHUB_API}/rate_limit", headers=_headers(), timeout=TIMEOUT)
    except requests.RequestException:
        return
    if r.status_code != 200:
        return
    remaining = r.json().get("resources", {}).get("core", {}).get("remaining", 999)
    if remaining < MIN_QUOTA_REMAINING:
        raise GitHubImportError(
            "GitHub API quota for this app is nearly exhausted right now "
            "(shared across all users). Please try again in a few minutes."
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
    _check_quota_before_fetch()
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

    skipped = max(0, len([
        node["path"] for node in tree
        if node.get("type") == "blob" and _is_iac_file(node["path"])
    ]) - MAX_FILES)

    summaries = []
    total_chars = 0
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
        if total_chars + len(block) > MAX_CHARS:
            log.warning(
                "GitHub import: character limit (%d) reached after %d files. "
                "Remaining files truncated.",
                MAX_CHARS, len(summaries)
            )
            break
        summaries.append(block)
        total_chars += len(block)

    if not summaries:
        raise GitHubImportError("Could not download any readable IaC files.")

    if skipped > 0:
        log.info("GitHub import: repo had %d IaC files, capped at %d. %d skipped.", 
                 skipped + MAX_FILES, MAX_FILES, skipped)

    header = f"Repository '{owner}/{repo}' contains the following infrastructure:\n\n"
    return header + "\n".join(summaries)