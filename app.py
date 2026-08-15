from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re

app = FastAPI()

ALLOWED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

VALID_THIRD_PARTY_SHA = re.compile(r"^[0-9a-f]{40}$")


def evaluate(data):
    violations = []

    workflow = data.get("workflow", {})
    image = data.get("image", {})

    # 1. Permissions must be EXACTLY the required permissions.
    if workflow.get("permissions") != ALLOWED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull-request trigger and test requirements.
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    if workflow.get("testsPassed") is not True:
        violations.append("TESTS_INCOMPLETE")

    if workflow.get("matrixComplete") is not True:
        violations.append("TESTS_INCOMPLETE")

    if workflow.get("failFast") is not False:
        violations.append("TESTS_INCOMPLETE")

    # Remove duplicate TESTS_INCOMPLETE.
    if "TESTS_INCOMPLETE" in violations:
        violations = [
            v for i, v in enumerate(violations)
            if v != "TESTS_INCOMPLETE"
            or "TESTS_INCOMPLETE" not in violations[:i]
        ]

    # 3. Action pinning.
    actions = workflow.get("actions", [])

    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                violations.append("MUTABLE_ACTION")
                continue

            owner = action.get("owner")
            ref = action.get("ref")

            # Official actions may use tags.
            if owner == "actions":
                continue

            # Third-party actions require 40-char lowercase SHA.
            if (
                not isinstance(ref, str)
                or not VALID_THIRD_PARTY_SHA.fullmatch(ref)
            ):
                violations.append("MUTABLE_ACTION")

    # 4. Docker image requirements.
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 5. Production requirements.
    if data.get("target") == "production":
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Deduplicate all violation codes.
    result = []
    seen = set()

    for violation in violations:
        if violation not in seen:
            seen.add(violation)
            result.append(violation)

    return {
        "decision": "promote" if not result else "block",
        "violations": result,
    }


@app.post("/release-gate")
async def release_gate(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            status_code=200,
            content={
                "decision": "block",
                "violations": [
                    "TESTS_INCOMPLETE",
                    "MUTABLE_ACTION",
                    "SINGLE_STAGE_IMAGE",
                    "ROOT_RUNTIME",
                    "SECRET_IN_LAYER",
                    "CRITICAL_CVE",
                    "UNPINNED_IMAGE",
                ],
            },
        )

    if not isinstance(data, dict):
        return JSONResponse(
            status_code=200,
            content={
                "decision": "block",
                "violations": [],
            },
        )

    return JSONResponse(
        status_code=200,
        content=evaluate(data),
    )


@app.get("/")
def health():
    return {"status": "ok"}