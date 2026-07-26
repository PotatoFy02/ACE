"""
RPM Engine — Required Permissions Manifest extractor.
Reads Python source files, finds boto3 SDK calls,
outputs a valid RPM dict that passes RPM.model_validate().

Uses recursive AST walking — no tree-sitter query API required.
Compatible with tree-sitter 0.26.
"""

import subprocess
import threading
import re
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from schemas.models import RPM, SDKCall, Confidence
from schemas.iam_mapping import resolve_iam_action


PY_LANGUAGE = Language(tspython.language())
_parser = Parser(PY_LANGUAGE)
PARSE_TIMEOUT_SECONDS = 0.5


def _text(node) -> str:
    return node.text.decode("utf-8") if node and node.text else ""


def _child_by_type(node, *types):
    for child in node.children:
        if child.type in types:
            return child
    return None


def _children_by_type(node, *types) -> list:
    return [c for c in node.children if c.type in types]


def _walk_all(node, collected: list, node_type: str):
    if node.type == node_type:
        collected.append(node)
    for child in node.children:
        _walk_all(child, collected, node_type)


def _extract_string_content(node) -> str | None:
    """
    AST: string -> string_start, string_content, string_end
    Returns the inner content only (no quotes).
    """
    if node is None or node.type != "string":
        return None
    content = _child_by_type(node, "string_content")
    return _text(content) if content else None


def _find_client_bindings(root) -> dict[str, str]:
    """
    Pass 1: find `varname = boto3.client('service')` bindings.

    AST shape:
      assignment
        identifier          <- var name
        call
          attribute
            identifier      <- "boto3"
            identifier      <- "client" or "resource"
          argument_list
            string          <- service name
    """
    bindings: dict[str, str] = {}
    assignments = []
    _walk_all(root, assignments, "assignment")

    for node in assignments:
        var_node = _child_by_type(node, "identifier")
        if not var_node:
            continue

        call_node = _child_by_type(node, "call")
        if not call_node:
            continue

        attr_node = _child_by_type(call_node, "attribute")
        if not attr_node:
            continue

        idents = _children_by_type(attr_node, "identifier")
        if len(idents) < 2:
            continue

        if _text(idents[0]) != "boto3":
            continue
        if _text(idents[1]) not in ("client", "resource"):
            continue

        arg_list = _child_by_type(call_node, "argument_list")
        if not arg_list:
            continue

        service_str_node = _child_by_type(arg_list, "string")
        service = _extract_string_content(service_str_node)
        if not service:
            continue

        bindings[_text(var_node)] = service

    return bindings


def _find_sdk_calls(root, bindings: dict[str, str]) -> list[dict]:
    """
    Pass 2: find method calls on bound client variables.

    AST shape for `s3_client.put_object(Bucket='x')`:
      call
        attribute
          identifier    <- must be in bindings
          identifier    <- method name
        argument_list
    """
    calls = []
    call_nodes = []
    _walk_all(root, call_nodes, "call")

    for node in call_nodes:
        attr_node = _child_by_type(node, "attribute")
        if not attr_node:
            continue

        idents = _children_by_type(attr_node, "identifier")
        if len(idents) < 2:
            continue

        obj = _text(idents[0])
        method = _text(idents[1])

        if obj not in bindings:
            continue

        arg_list = _child_by_type(node, "argument_list")
        args_text = _text(arg_list) if arg_list else ""

        calls.append({
            "service": bindings[obj],
            "method": method,
            "args_text": args_text,
        })

    return calls


def _extract_resource_arn(service: str, args_text: str) -> tuple[list[str], bool, str]:
    hardcoded = re.findall(
        r"(?:Bucket|TableName|FunctionName|KeyId)\s*=\s*['\"]([^'\"]+)['\"]",
        args_text
    )
    if hardcoded:
        name = hardcoded[0]
        if service == "s3":
            return ([f"arn:aws:s3:::{name}/*"], False, "high")
        elif service == "dynamodb":
            return ([f"arn:aws:dynamodb:*:*:table/{name}"], False, "high")
        elif service == "lambda":
            return ([f"arn:aws:lambda:*:*:function:{name}"], False, "high")
        else:
            return ([f"arn:aws:{service}:::*"], False, "high")

    if re.search(r"os\.environ|os\.getenv|environ\.get", args_text):
        return (["*"], True, "medium")

    return (["*"], True, "medium")


def _get_commit_sha(repo_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def parse_python_file(file_path: str, repo_path: str = ".") -> RPM:
    path = Path(file_path)
    source = path.read_bytes()

    result: dict = {}
    error: dict = {}

    def _parse():
        try:
            tree = _parser.parse(source)
            bindings = _find_client_bindings(tree.root_node)
            raw_calls = _find_sdk_calls(tree.root_node, bindings)
            result["raw_calls"] = raw_calls
        except Exception as e:
            error["e"] = e

    thread = threading.Thread(target=_parse)
    thread.start()
    thread.join(timeout=PARSE_TIMEOUT_SECONDS)

    if thread.is_alive():
        raise TimeoutError(f"Parser exceeded {PARSE_TIMEOUT_SECONDS}s on {file_path}")
    if "e" in error:
        raise error["e"]

    confidence_rank = {"high": 2, "medium": 1, "low": 0}
    sdk_calls = []

    for call in result.get("raw_calls", []):
        action_iam, base_confidence = resolve_iam_action(
            call["service"], call["method"]
        )
        resources, resources_wildcard, resource_confidence = _extract_resource_arn(
            call["service"], call["args_text"]
        )
        final_confidence = min(
            [base_confidence, resource_confidence],
            key=lambda c: confidence_rank[c]
        )
        sdk_calls.append(SDKCall(
            service=call["service"],
            action=call["method"],
            action_iam=action_iam,
            resources=resources,
            resources_wildcard=resources_wildcard,
            confidence=Confidence(final_confidence)
        ))

    rpm = RPM(
        service_name=path.stem,
        language="python",
        commit_sha=_get_commit_sha(repo_path),
        sdk_calls=sdk_calls
    )
    RPM.model_validate(rpm.model_dump())
    return rpm