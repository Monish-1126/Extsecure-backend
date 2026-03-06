import os
import json
import struct
import zipfile
import requests
import joblib
import pandas as pd

from fastapi.responses import JSONResponse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ======================================================
# CONFIG
# ======================================================
TMP_DIR = "/tmp"
MODEL_PATH = "xgb_extension_model.pkl"
FEATURE_COLUMNS_PATH = "feature_columns.pkl"

OFFICIAL_UPDATE_URL = "https://clients2.google.com/service/update2/crx"

HIGH_RISK_PERMISSIONS = {
    "webRequest",
    "webRequestBlocking",
    "cookies",
    "tabs",
    "<all_urls>",
    "history",
    "downloads",
    "proxy",
    "management",
    "bookmarks"
}

# ======================================================
# LOAD MODEL & COLUMNS (ONCE)
# ======================================================
model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

# ======================================================
# FASTAPI APP
# ======================================================
app = FastAPI(title="Malicious Extension Detection API")

# ======================================================
# REQUEST / RESPONSE MODELS
# ======================================================
class AnalyzeRequest(BaseModel):
    extension_id: str


class AnalyzeResponse(BaseModel):
    extension_id: str
    extension_name: str
    description: str
    version: str
    permissions: list[str]
    risk_score: float
    risk_level: str


# ======================================================
# 1. DOWNLOAD CRX
# ======================================================
def download_crx(extension_id: str, out_path: str):
    url = (
        "https://clients2.google.com/service/update2/crx"
        "?response=redirect"
        "&prodversion=114.0"
        "&acceptformat=crx2,crx3"
        f"&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
    )

    try:
        r = requests.get(url, timeout=20)

        if r.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail=f"Extension {extension_id} not found in Chrome Web Store"
            )

        if r.status_code != 200 or len(r.content) < 100:
            raise HTTPException(
                status_code=400,
                detail="Invalid extension ID or CRX download failed"
            )
        
        with open(out_path, "wb") as f:
            f.write(r.content)

    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504,
            detail="Chrome Web Store request timed out"
        )

    except requests.exceptions.RequestException:
        raise HTTPException(
            status_code=500,
            detail="Failed to download extension"
        )


# ======================================================
# 2. CRX → ZIP
# ======================================================
def crx_to_zip(crx_path: str, zip_path: str):
    with open(crx_path, "rb") as f:
        if f.read(4) != b"Cr24":
            raise HTTPException(
            status_code=400,
            detail="Invalid extension ID or corrupted CRX file"
        )

        version = struct.unpack("<I", f.read(4))[0]

        if version == 2:
            pub_len = struct.unpack("<I", f.read(4))[0]
            sig_len = struct.unpack("<I", f.read(4))[0]
            f.read(pub_len + sig_len)

        elif version == 3:
            header_size = struct.unpack("<I", f.read(4))[0]
            f.read(header_size)

        else:
            raise HTTPException(
                status_code=400,
                detail="Unsupported CRX format"
            )

        zip_data = f.read()

    with open(zip_path, "wb") as z:
        z.write(zip_data)


# ======================================================
# 3. EXTRACT MANIFEST
# ======================================================
def extract_manifest(zip_path: str) -> dict:
    with zipfile.ZipFile(zip_path, "r") as z:
        if "manifest.json" not in z.namelist():
            raise HTTPException(
            status_code=400,
            detail="Invalid extension package (manifest.json missing)"
        )

        with z.open("manifest.json") as f:
            return json.load(f)

def resolve_localized_string(zip_path: str, value: str) -> str:
    if not value.startswith("__MSG_"):
        return value

    key = value.replace("__MSG_", "").replace("__", "")

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            locale_files = [f for f in z.namelist() if f.endswith("messages.json")]

            for file in locale_files:
                with z.open(file) as f:
                    messages = json.load(f)
                    if key in messages:
                        return messages[key].get("message", value)
    except Exception:
        pass

    return value
# ======================================================
# 4. FEATURE EXTRACTION (DATASET-STYLE)
# ======================================================
def extract_features_from_manifest(manifest: dict) -> dict:
    features = {}

    features["manifest_version"] = manifest.get("manifest_version", 0)

    permissions = manifest.get("permissions", [])
    host_permissions = manifest.get("host_permissions", [])
    all_permissions = permissions + host_permissions

    perm_count = len(all_permissions)

    features["permission_count"] = perm_count
    features["api_permission_count"] = len(permissions)
    features["host_permission_count"] = len(host_permissions)
    features["unique_permission_types"] = len(set(all_permissions))

    features["host_to_api_ratio"] = len(host_permissions) / (len(permissions) + 1)

    high_risk_count = sum(1 for p in all_permissions if p in HIGH_RISK_PERMISSIONS)
    features["high_risk_permission_count"] = high_risk_count
    features["risk_density"] = high_risk_count / (perm_count + 1)

    features["has_all_urls"] = int("<all_urls>" in all_permissions)
    features["has_tabs"] = int("tabs" in all_permissions)
    features["has_cookies"] = int("cookies" in all_permissions)
    features["has_webRequest"] = int("webRequest" in all_permissions)
    features["has_webRequestBlocking"] = int("webRequestBlocking" in all_permissions)
    features["has_history"] = int("history" in all_permissions)

    # -------- CONTENT SCRIPTS --------
    content_scripts = manifest.get("content_scripts", [])
    features["content_script_count"] = len(content_scripts)

    total_js = 0
    total_matches = 0
    inject_all_domains = 0

    for script in content_scripts:
        total_js += len(script.get("js", []))
        matches = script.get("matches", [])
        total_matches += len(matches)

        if "*://*/*" in matches or "<all_urls>" in matches:
            inject_all_domains = 1

    features["content_script_js_count"] = total_js
    features["match_count"] = total_matches
    features["injects_all_domains"] = inject_all_domains
    features["broad_match_ratio"] = inject_all_domains * total_matches

    features["script_density"] = total_js / (perm_count + 1)

    # -------- BACKGROUND --------
    background = manifest.get("background", {})
    features["has_background"] = int(bool(background))

    if isinstance(background, dict):
        bg_scripts = background.get("scripts", [])
        features["background_script_count"] = len(bg_scripts)
        features["background_persistent"] = int(background.get("persistent", False))
    else:
        features["background_script_count"] = 0
        features["background_persistent"] = 0

    features["background_density"] = (
        features["background_script_count"] / (perm_count + 1)
    )

    # -------- INTERACTIONS --------
    features["broad_and_webrequest"] = features["has_all_urls"] * features["has_webRequest"]
    features["broad_and_background"] = features["has_all_urls"] * features["has_background"]
    features["persistent_and_webrequest"] = (
        features["background_persistent"] * features["has_webRequest"]
    )
    features["cookies_and_tabs"] = features["has_cookies"] * features["has_tabs"]
    features["history_and_webrequest"] = features["has_history"] * features["has_webRequest"]

    # -------- CSP --------
    csp = manifest.get("content_security_policy", "")
    csp_risk = 0
    if "unsafe-eval" in str(csp):
        csp_risk += 1
    if "unsafe-inline" in str(csp):
        csp_risk += 1

    features["has_csp"] = int(bool(csp))
    features["csp_risk_score"] = csp_risk

    # -------- UPDATE --------
    update_url = manifest.get("update_url", "")
    features["has_update_url"] = int(bool(update_url))
    features["is_offstore_update"] = int(
        update_url != "" and update_url != OFFICIAL_UPDATE_URL
    )

    return features


# ======================================================
# 5. FEATURE ALIGNMENT
# ======================================================
def align_features(features: dict) -> pd.DataFrame:
    row = [features.get(col, 0) for col in feature_columns]
    return pd.DataFrame([row], columns=feature_columns)


# ======================================================
# 6. RISK LEVEL MAPPING
# ======================================================
def risk_level_from_score(p: float) -> str:
    if p >= 0.80:
        return "CRITICAL"
    elif p >= 0.60:
        return "HIGH"
    elif p >= 0.40:
        return "MEDIUM"
    else:
        return "LOW"


# ======================================================
# 7. FULL PIPELINE
# ======================================================
def analyze_extension(extension_id: str) -> dict:
    os.makedirs(TMP_DIR, exist_ok=True)

    crx_path = os.path.join(TMP_DIR, f"{extension_id}.crx")
    zip_path = os.path.join(TMP_DIR, f"{extension_id}.zip")

    download_crx(extension_id, crx_path)
    crx_to_zip(crx_path, zip_path)
    manifest = extract_manifest(zip_path)

    features = extract_features_from_manifest(manifest)
    X = align_features(features)

    risk_score = float(model.predict_proba(X)[0][1])
    risk_level = risk_level_from_score(risk_score)

    permissions = manifest.get("permissions") or []
    host_permissions = manifest.get("host_permissions") or []
    raw_name = manifest.get("name", "Unknown")
    raw_desc = manifest.get("description", "No description available")

    extension_name = resolve_localized_string(zip_path, raw_name)
    description = resolve_localized_string(zip_path, raw_desc)
    return {
        "extension_id": extension_id,
        "extension_name": extension_name,
        "description": description,
        "version": manifest.get("version", "N/A"),
        "permissions": (manifest.get("permissions") or []) +
                    (manifest.get("host_permissions") or []),
        "risk_score": round(risk_score, 4),
        "risk_level": risk_level
    }


# ======================================================
# 8. API ENDPOINT
# ======================================================
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    try:
        return analyze_extension(req.extension_id)

    # IMPORTANT: rethrow existing HTTP exceptions
    except HTTPException as e:
        raise e

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail="Downloaded CRX is invalid"
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected server error: {str(e)}"
        )
    

@app.get("/health")
def health():
    print("🔥 HEALTH CHECK HIT")
    return {"status": "ok"}