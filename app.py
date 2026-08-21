from fastapi import FastAPI
from typing import Any

app = FastAPI(title="Release Gate")


VIOLATIONS = [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
]


@app.get("/")
def root():
    return {"service": "release-gate", "status": "ok"}


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Permissions must be exactly:
    # contents=read, packages=write, id-token=none
    permissions = workflow.get("permissions", {})
    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if permissions != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request
    if payload.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests, matrix and failFast
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner == "actions":
            # Official actions may use version tags.
            continue

        # Third-party actions require a 40-character lowercase SHA.
        if (
            len(ref) != 40
            or any(c not in "0123456789abcdef" for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image must be multi-stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Image must run as non-root
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secret handling
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. Critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. Digest pinning
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10. Production requirements
    if payload.get("target") == "production":
        if (
            payload.get("event") != "push"
            or workflow.get("trigger") != "push"
            or payload.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving deterministic order.
    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }