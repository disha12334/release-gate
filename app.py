from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Optional

app = FastAPI(title="TDS GA7 Release Gate")


class Action(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[Action]
    environmentApproval: Optional[bool] = None


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image


EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def is_full_sha(value: str) -> bool:
    return (
        len(value) == 40
        and all(c in "0123456789abcdef" for c in value)
    )


@app.get("/")
def root():
    return {"service": "release-gate", "status": "ok"}


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    violations = []

    # ---------------------------------------------------------
    # 1. EXACT least-privilege permissions
    # ---------------------------------------------------------
    if req.workflow.permissions != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull request security + complete testing
    # ---------------------------------------------------------
    if req.event == "pull_request":
        if req.workflow.trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        if (
            req.workflow.testsPassed is not True
            or req.workflow.matrixComplete is not True
            or req.workflow.failFast is not False
        ):
            violations.append("TESTS_INCOMPLETE")

    # Explicitly reject pull_request_target
    if req.workflow.trigger == "pull_request_target":
        if "UNSAFE_PR_TRIGGER" not in violations:
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. Action pinning
    #
    # actions/* may use version tags.
    # Third-party actions MUST use 40-char lowercase SHA.
    # ---------------------------------------------------------
    for action in req.workflow.actions:
        if action.owner != "actions":
            if not is_full_sha(action.ref):
                violations.append("MUTABLE_ACTION")
                break

    # ---------------------------------------------------------
    # 4. Hardened image
    # ---------------------------------------------------------
    if req.image.multiStage is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if req.image.runsAsRoot is not False:
        violations.append("ROOT_RUNTIME")

    # Allowed: none OR buildkit
    if req.image.secretMode not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")

    if req.image.criticalVulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    if req.image.digestPinned is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 5. Production-specific rules
    # ---------------------------------------------------------
    if req.target == "production":
        if not (
            req.event == "push"
            and req.ref == "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if req.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # Deterministic result
    # ---------------------------------------------------------
    return {
        "decision": "promote" if len(violations) == 0 else "block",
        "violations": violations,
    }