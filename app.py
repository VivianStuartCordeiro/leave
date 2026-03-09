import os
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime
import uuid
import traceback
import logging
from werkzeug.utils import secure_filename
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()
app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.path.join(BASE_DIR, "leave_policy.json")
AUDIT_FILE = os.path.join(BASE_DIR, "audit_log.jsonl")
NOTIFICATION_FILE = os.path.join(BASE_DIR, "notifications.jsonl")
PROOF_META_FILE = os.path.join(BASE_DIR, "proof_meta.json")
IDENTITY_MAP_FILE = os.path.join(BASE_DIR, "identity_map.json")
LOCAL_LEAVE_FILE = os.path.join(BASE_DIR, "leave_requests_local.json")
PROOF_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "proofs")
ALLOWED_PROOF_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
MAX_PROOF_FILE_SIZE_BYTES = 5 * 1024 * 1024
LOGIN_RATE_WINDOW_SECONDS = 10 * 60
LOGIN_RATE_MAX_ATTEMPTS = 6
LOGIN_ATTEMPTS = defaultdict(deque)

# Allows your frontend (port 5500) to communicate with this server (port 5000)
CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:3000"]}})

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

# Validate that credentials are loaded
if not url or not key:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY environment variables are required!")

try:
    supabase: Client = create_client(url, key)
    logger.info("Supabase client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise


def _extract_bearer_token() -> str | None:
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None


def _get_current_user(token: str):
    return supabase.auth.get_user(token).user


def _manager_id_from_user_id(user_id: str) -> str:
    # Deterministic manager code so every manager always has an ID.
    return f"MGR-{user_id.replace('-', '')[:8].upper()}"


def _employee_id_from_user_id(user_id: str) -> str:
    # Deterministic employee code so every employee always has an ID.
    return f"EMP-{user_id.replace('-', '')[:8].upper()}"


def _parse_contact_meta(raw_value: str):
    meta = {
        "email": "",
        "employee_id": "",
        "manager_id": "",
        "phone": "",
        "employment_status": "active"
    }
    if not raw_value:
        return meta

    if "::" not in raw_value:
        if "@" in raw_value:
            meta["email"] = raw_value
        else:
            meta["phone"] = raw_value
        return meta

    for part in raw_value.split("||"):
        if "::" not in part:
            continue
        key, value = part.split("::", 1)
        key = key.strip()
        value = value.strip()
        if key in meta:
            meta[key] = value
    return meta


def _build_contact_meta(email="", employee_id="", manager_id="", phone="", employment_status="active"):
    pieces = []
    if email:
        pieces.append(f"email::{email}")
    if employee_id:
        pieces.append(f"employee_id::{employee_id}")
    if manager_id:
        pieces.append(f"manager_id::{manager_id}")
    if phone:
        pieces.append(f"phone::{phone}")
    pieces.append(f"employment_status::{employment_status or 'active'}")
    return "||".join(pieces)


def _build_contact_meta_from_meta(meta: dict):
    pieces = []
    if meta.get("email"):
        pieces.append(f"email::{meta.get('email')}")
    if meta.get("employee_id"):
        pieces.append(f"employee_id::{meta.get('employee_id')}")
    if meta.get("manager_id"):
        pieces.append(f"manager_id::{meta.get('manager_id')}")
    if meta.get("phone"):
        pieces.append(f"phone::{meta.get('phone')}")
    pieces.append(f"employment_status::{meta.get('employment_status', 'active')}")
    return "||".join(pieces)


def _find_user_email_by_employee_id(employee_id: str):
    mapping = _load_identity_map().get("by_employee_id", {})
    if employee_id in mapping:
        rec = mapping[employee_id]
        return rec.get("email"), rec.get("user_id")
    rows = supabase.table('user_settings').select("user_id,phone").execute()
    for row in (rows.data or []):
        meta = _parse_contact_meta(row.get("phone", ""))
        if meta.get("employee_id") == employee_id:
            return meta.get("email"), row.get("user_id")
    return None, None


def _find_user_setting_by_employee_id(employee_id: str):
    mapped = _load_identity_map().get("by_employee_id", {}).get(employee_id)
    if mapped and mapped.get("user_id"):
        row = supabase.table('user_settings').select("*").eq("user_id", mapped["user_id"]).limit(1).execute()
        if row.data:
            return row.data[0], _identity_for_user(mapped["user_id"])
    rows = supabase.table('user_settings').select("*").execute()
    for row in (rows.data or []):
        meta = _parse_contact_meta(row.get("phone", ""))
        if meta.get("employee_id") == employee_id:
            return row, meta
    return None, None


def _find_user_email_by_manager_id(manager_id: str):
    mapping = _load_identity_map().get("by_manager_id", {})
    if manager_id in mapping:
        rec = mapping[manager_id]
        return rec.get("email"), rec.get("user_id")
    rows = supabase.table('user_settings').select("user_id,phone").execute()
    for row in (rows.data or []):
        meta = _parse_contact_meta(row.get("phone", ""))
        if meta.get("manager_id") == manager_id:
            return meta.get("email"), row.get("user_id")
    return None, None


def _find_manager_user_ids_by_manager_id(manager_id: str):
    mapping = _load_identity_map().get("by_manager_id", {})
    if manager_id in mapping and mapping[manager_id].get("user_id"):
        return [mapping[manager_id]["user_id"]]
    rows = supabase.table('user_settings').select("user_id,phone").execute()
    user_ids = []
    for row in (rows.data or []):
        meta = _parse_contact_meta(row.get("phone", ""))
        if meta.get("manager_id") == manager_id:
            user_ids.append(row.get("user_id"))
    return [u for u in user_ids if u]


def _identity_meta_for_user(user_id: str):
    mapped = _identity_for_user(user_id)
    if mapped:
        return mapped
    row = supabase.table('user_settings').select("phone").eq("user_id", user_id).limit(1).execute()
    if not row.data:
        return {}
    return _parse_contact_meta(row.data[0].get("phone", ""))


def _is_manager_user(user_id: str) -> bool:
    meta = _identity_meta_for_user(user_id)
    expected = _manager_id_from_user_id(user_id)
    return bool(meta.get("manager_id")) and meta.get("manager_id") == expected


def _is_employee_user(user_id: str) -> bool:
    meta = _identity_meta_for_user(user_id)
    return bool(meta.get("employee_id"))


def _can_attempt_login(login_key: str):
    now = datetime.now().timestamp()
    bucket = LOGIN_ATTEMPTS[login_key]
    while bucket and (now - bucket[0]) > LOGIN_RATE_WINDOW_SECONDS:
        bucket.popleft()
    return len(bucket) < LOGIN_RATE_MAX_ATTEMPTS


def _record_login_attempt(login_key: str):
    LOGIN_ATTEMPTS[login_key].append(datetime.now().timestamp())


def _is_rls_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "row-level security" in text or "'code': '42501'" in text or '"code": "42501"' in text


def _load_local_leave_requests():
    if not os.path.exists(LOCAL_LEAVE_FILE):
        return []
    try:
        with open(LOCAL_LEAVE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_local_leave_requests(rows):
    with open(LOCAL_LEAVE_FILE, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)


def _leave_select_all():
    try:
        result = supabase.table('leave_requests').select("*").execute()
        return result.data or []
    except Exception as e:
        if _is_rls_error(e):
            return _load_local_leave_requests()
        raise


def _leave_select_by_user(user_id: str):
    rows = _leave_select_all()
    return [r for r in rows if r.get("user_id") == user_id]


def _leave_select_by_id(request_id: str):
    rows = _leave_select_all()
    for row in rows:
        if row.get("id") == request_id:
            return row
    return None


def _leave_insert(row: dict):
    try:
        result = supabase.table('leave_requests').insert(row).execute()
        return (result.data or [row])[0]
    except Exception as e:
        if not _is_rls_error(e):
            raise
        rows = _load_local_leave_requests()
        rows.append(row)
        _save_local_leave_requests(rows)
        return row


def _leave_update_by_id(request_id: str, updates: dict):
    try:
        result = supabase.table('leave_requests').update(updates).eq("id", request_id).execute()
        return (result.data or [None])[0]
    except Exception as e:
        if not _is_rls_error(e):
            raise
        rows = _load_local_leave_requests()
        updated_row = None
        for idx, row in enumerate(rows):
            if row.get("id") == request_id:
                row.update(updates)
                rows[idx] = row
                updated_row = row
                break
        if updated_row is not None:
            _save_local_leave_requests(rows)
        return updated_row


def _load_identity_map():
    if not os.path.exists(IDENTITY_MAP_FILE):
        return {"by_user_id": {}, "by_manager_id": {}, "by_employee_id": {}}
    try:
        with open(IDENTITY_MAP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"by_user_id": {}, "by_manager_id": {}, "by_employee_id": {}}
        data.setdefault("by_user_id", {})
        data.setdefault("by_manager_id", {})
        data.setdefault("by_employee_id", {})
        return data
    except Exception:
        return {"by_user_id": {}, "by_manager_id": {}, "by_employee_id": {}}


def _save_identity_map(data):
    with open(IDENTITY_MAP_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _record_identity(
    user_id: str,
    email: str = "",
    manager_id: str = "",
    employee_id: str = "",
    employment_status: str = "active",
    full_name: str = "",
    department: str = ""
):
    mapping = _load_identity_map()
    user_entry = mapping["by_user_id"].get(user_id, {})
    user_entry.update({
        "user_id": user_id,
        "email": email or user_entry.get("email", ""),
        "manager_id": manager_id or user_entry.get("manager_id", ""),
        "employee_id": employee_id or user_entry.get("employee_id", ""),
        "employment_status": employment_status or user_entry.get("employment_status", "active"),
        "full_name": full_name or user_entry.get("full_name", ""),
        "department": department or user_entry.get("department", "")
    })
    mapping["by_user_id"][user_id] = user_entry
    if user_entry.get("manager_id"):
        mapping["by_manager_id"][user_entry["manager_id"]] = {
            "user_id": user_id,
            "email": user_entry.get("email", "")
        }
    if user_entry.get("employee_id"):
        mapping["by_employee_id"][user_entry["employee_id"]] = {
            "user_id": user_id,
            "email": user_entry.get("email", "")
        }
    _save_identity_map(mapping)


def _identity_for_user(user_id: str):
    mapping = _load_identity_map()
    return mapping.get("by_user_id", {}).get(user_id, {})


def _upsert_identity_record(user_id: str, email: str, manager_id: str = "", employee_id: str = ""):
    old = {}
    try:
        existing = supabase.table('user_settings').select("*").eq("user_id", user_id).limit(1).execute()
        old = existing.data[0] if existing.data else {}
    except Exception as e:
        logger.warning(f"user_settings read skipped due to RLS/permission: {str(e)}")
    old_meta = _identity_for_user(user_id) or _parse_contact_meta(old.get("phone", ""))
    merged_meta = {
        "email": email or old_meta.get("email", ""),
        "employee_id": employee_id or old_meta.get("employee_id", ""),
        "manager_id": manager_id or old_meta.get("manager_id", ""),
        "phone": (old.get("phone", "") or old_meta.get("phone", ""))[:20],
        "employment_status": old_meta.get("employment_status", "active")
    }
    _record_identity(
        user_id=user_id,
        email=merged_meta["email"],
        manager_id=merged_meta["manager_id"],
        employee_id=merged_meta["employee_id"],
        employment_status=merged_meta["employment_status"]
    )
    payload = {
        "user_id": user_id,
        "full_name": old.get("full_name", "") or email.split("@")[0],
        "phone": merged_meta["phone"],
        "department": old.get("department", ""),
        "profile_picture": old.get("profile_picture", ""),
        "updated_at": datetime.now().isoformat()
    }
    try:
        existing = supabase.table('user_settings').select("user_id").eq("user_id", user_id).limit(1).execute()
        if existing.data:
            supabase.table('user_settings').update(payload).eq("user_id", user_id).execute()
        else:
            supabase.table('user_settings').insert(payload).execute()
    except Exception as e:
        logger.warning(f"user_settings write skipped due to RLS/permission: {str(e)}")


def _employee_ids_for_manager(manager_id: str) -> list[str]:
    mapped_ids = []
    identity_map = _load_identity_map().get("by_user_id", {})
    for uid, rec in identity_map.items():
        if rec.get("manager_id") == manager_id and rec.get("employee_id"):
            mapped_ids.append(uid)
    if mapped_ids:
        return mapped_ids
    # NOTE: Uses user_settings.profile_picture as assigned_manager_id storage
    # to avoid requiring an immediate DB schema migration.
    assigned = supabase.table('user_settings').select("user_id").eq("profile_picture", manager_id).execute()
    return [row["user_id"] for row in (assigned.data or []) if row.get("user_id")]


def _manager_scoped_requests(manager_id: str):
    employee_ids = _employee_ids_for_manager(manager_id)
    if not employee_ids:
        return []
    result = _leave_select_all()
    return [row for row in (result or []) if row.get("user_id") in employee_ids]


DEFAULT_LEAVE_POLICY = {
    "version": 1,
    "workflow": {
        "approval_levels": 2
    },
    "constraints": {
        "max_parallel_leaves_per_department": 3,
        "blackout_dates": []
    },
    "leave_types": {
        "Sick": {"annual_quota": 12, "max_consecutive_days": 10, "requires_document_after_days": 2},
        "Vacation": {"annual_quota": 20, "max_consecutive_days": 20, "requires_document_after_days": 0},
        "Personal": {"annual_quota": 6, "max_consecutive_days": 5, "requires_document_after_days": 0},
        "Casual": {"annual_quota": 8, "max_consecutive_days": 5, "requires_document_after_days": 0},
        "Maternity": {"annual_quota": 90, "max_consecutive_days": 90, "requires_document_after_days": 1},
        "Paternity": {"annual_quota": 15, "max_consecutive_days": 15, "requires_document_after_days": 1}
    }
}


def _load_leave_policy():
    if not os.path.exists(POLICY_FILE):
        return DEFAULT_LEAVE_POLICY
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("leave_types"), dict) and data["leave_types"]:
            return data
        return DEFAULT_LEAVE_POLICY
    except Exception:
        return DEFAULT_LEAVE_POLICY


def _save_leave_policy(policy_data):
    with open(POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(policy_data, f, indent=2)


def _append_audit_log(event_type: str, actor_id: str, actor_role: str, details: dict | None = None):
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "actor_id": actor_id or "",
        "actor_role": actor_role or "",
        "details": details or {}
    }
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _read_audit_logs(limit: int = 200):
    if not os.path.exists(AUDIT_FILE):
        return []
    rows = []
    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    rows.reverse()
    return rows[:max(1, min(limit, 1000))]


def _append_notification(recipient_user_id: str, title: str, message: str, kind: str = "info", meta: dict | None = None):
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "recipient_user_id": recipient_user_id,
        "title": title,
        "message": message,
        "kind": kind,
        "read": False,
        "meta": meta or {}
    }
    with open(NOTIFICATION_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _read_notifications_for_user(user_id: str, limit: int = 100):
    if not os.path.exists(NOTIFICATION_FILE):
        return []
    rows = []
    with open(NOTIFICATION_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            if item.get("recipient_user_id") == user_id:
                rows.append(item)
    rows.reverse()
    return rows[:max(1, min(limit, 300))]


def _rewrite_notification_file(updated_rows):
    with open(NOTIFICATION_FILE, "w", encoding="utf-8") as f:
        for row in updated_rows:
            f.write(json.dumps(row) + "\n")


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"
    return response


def _load_proof_meta():
    if not os.path.exists(PROOF_META_FILE):
        return {}
    try:
        with open(PROOF_META_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_proof_meta(data):
    with open(PROOF_META_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _get_proof_record(leave_request_id: str):
    data = _load_proof_meta()
    return data.get(leave_request_id)


def _set_proof_record(leave_request_id: str, record: dict):
    data = _load_proof_meta()
    data[leave_request_id] = record
    _save_proof_meta(data)


def _enrich_requests_with_proof(rows):
    enriched = []
    for row in (rows or []):
        item = dict(row)
        proof = _get_proof_record(item.get("id", ""))
        item["proof_status"] = (proof or {}).get("status", "not_submitted")
        item["proof_required"] = bool((proof or {}).get("required", False))
        item["proof_uploaded_at"] = (proof or {}).get("uploaded_at")
        enriched.append(item)
    return enriched


def _validate_leave_policy(policy_data):
    if not isinstance(policy_data, dict):
        return "Policy must be an object"
    leave_types = policy_data.get("leave_types")
    if not isinstance(leave_types, dict) or not leave_types:
        return "leave_types must be a non-empty object"
    constraints = policy_data.get("constraints", {})
    workflow = policy_data.get("workflow", {})
    if workflow and not isinstance(workflow, dict):
        return "workflow must be an object"
    if workflow:
        levels = workflow.get("approval_levels", 1)
        if not isinstance(levels, int) or levels < 1 or levels > 5:
            return "workflow.approval_levels must be an integer between 1 and 5"
    if constraints and not isinstance(constraints, dict):
        return "constraints must be an object"
    if constraints:
        parallel = constraints.get("max_parallel_leaves_per_department", 0)
        if not isinstance(parallel, int) or parallel < 1:
            return "constraints.max_parallel_leaves_per_department must be an integer >= 1"
        blackout = constraints.get("blackout_dates", [])
        if not isinstance(blackout, list):
            return "constraints.blackout_dates must be an array"
        for entry in blackout:
            if not isinstance(entry, str) or not _safe_date(entry):
                return "constraints.blackout_dates must contain valid YYYY-MM-DD strings"
    for leave_type, rules in leave_types.items():
        if not isinstance(leave_type, str) or not leave_type.strip():
            return "Each leave type must have a valid name"
        if not isinstance(rules, dict):
            return f"Rules for {leave_type} must be an object"
        for field in ["annual_quota", "max_consecutive_days", "requires_document_after_days"]:
            if field not in rules:
                return f"{leave_type} missing {field}"
            if not isinstance(rules[field], int) or rules[field] < 0:
                return f"{leave_type}.{field} must be a non-negative integer"
    return None


def _get_leave_type_rules(leave_type: str):
    return _load_leave_policy().get("leave_types", {}).get(leave_type)


def _get_required_approval_levels() -> int:
    policy = _load_leave_policy()
    return int(policy.get("workflow", {}).get("approval_levels", 1))


def _pending_status(level: int, total_levels: int) -> str:
    return f"pending_l{level}_of_{total_levels}"


def _parse_pending_status(status: str):
    if not status:
        return None
    if status == "pending":
        return 1, 1
    if not status.startswith("pending_l") or "_of_" not in status:
        return None
    try:
        left, right = status.replace("pending_l", "", 1).split("_of_", 1)
        return int(left), int(right)
    except Exception:
        return None


def _date_ranges_overlap(start_a: str, end_a: str, start_b: str, end_b: str) -> bool:
    a1 = _safe_date(start_a)
    a2 = _safe_date(end_a)
    b1 = _safe_date(start_b)
    b2 = _safe_date(end_b)
    if not a1 or not a2 or not b1 or not b2:
        return False
    return a1 <= b2 and b1 <= a2


def _date_range_has_blackout(start_date: str, end_date: str, blackout_dates) -> bool:
    start = _safe_date(start_date)
    end = _safe_date(end_date)
    if not start or not end or end < start:
        return False
    blackout_set = {d for d in blackout_dates if _safe_date(d)}
    current = start
    while current <= end:
        if current.isoformat() in blackout_set:
            return True
        current = current.fromordinal(current.toordinal() + 1)
    return False


def _proof_required_for_request(leave_type: str, start_date: str, end_date: str) -> bool:
    rules = _get_leave_type_rules(leave_type) or {}
    threshold = int(rules.get("requires_document_after_days", 0))
    if threshold <= 0:
        return False
    return _requested_days(start_date, end_date) > threshold


def _safe_date(value: str):
    try:
        return datetime.fromisoformat(value).date()
    except Exception:
        return None


def _requested_days(start_date: str, end_date: str) -> int:
    start = _safe_date(start_date)
    end = _safe_date(end_date)
    if not start or not end:
        return 0
    if end < start:
        return 0
    return (end - start).days + 1


def _init_tracker(year: int):
    by_type = {}
    leave_types = _load_leave_policy().get("leave_types", {})
    for leave_type, rules in leave_types.items():
        quota = int(rules.get("annual_quota", 0))
        by_type[leave_type] = {
            "quota": quota,
            "approved_days": 0,
            "pending_days": 0,
            "declined_days": 0,
            "remaining_days": quota,
        }
    return {"year": year, "by_type": by_type}


def _build_tracker_from_requests(requests_data, year: int):
    tracker = _init_tracker(year)

    for req in (requests_data or []):
        leave_type = req.get("leave_type")
        if leave_type not in tracker["by_type"]:
            continue

        start_date = _safe_date(req.get("start_date", ""))
        if not start_date or start_date.year != year:
            continue

        days = _requested_days(req.get("start_date", ""), req.get("end_date", ""))
        status = (req.get("status") or "").lower()
        item = tracker["by_type"][leave_type]
        if status == "approved":
            item["approved_days"] += days
        elif status == "pending" or status.startswith("pending_"):
            item["pending_days"] += days
        elif status == "declined":
            item["declined_days"] += days

    for leave_type, item in tracker["by_type"].items():
        item["remaining_days"] = max(item["quota"] - item["approved_days"], 0)

    return tracker


def _require_manager_auth():
    token = _extract_bearer_token()
    if not token:
        return None, None, (jsonify({"message": "Unauthorized - Missing token"}), 401)
    manager_user = _get_current_user(token)
    if not manager_user:
        return None, None, (jsonify({"message": "Unauthorized - Invalid token"}), 401)
    if not _is_manager_user(manager_user.id):
        return None, None, (jsonify({"message": "Forbidden - manager access required"}), 403)
    manager_id = _manager_id_from_user_id(manager_user.id)
    return manager_user, manager_id, None


def _require_auth_user():
    token = _extract_bearer_token()
    if not token:
        return None, (jsonify({"message": "Unauthorized - Missing token"}), 401)
    current_user = _get_current_user(token)
    if not current_user:
        return None, (jsonify({"message": "Unauthorized - Invalid token"}), 401)
    return current_user, None


def _require_employee_auth():
    current_user, auth_error = _require_auth_user()
    if auth_error:
        return None, auth_error
    if not _is_employee_user(current_user.id):
        return None, (jsonify({"message": "Forbidden - employee access required"}), 403)
    return current_user, None

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/auth/admin/login', methods=['POST'])
def admin_login():
    """Admin/Manager login with access code"""
    data = request.json
    
    if data.get("accessCode") != "12345678":
        return jsonify({"message": "Invalid Approval Code"}), 403
    
    try:
        manager_id_input = (data.get("managerId") or "").strip().upper()
        email = (data.get("email") or "").strip().lower()
        login_key = f"admin::{manager_id_input or email or 'unknown'}"
        if not _can_attempt_login(login_key):
            return jsonify({"message": "Too many login attempts. Please try again later."}), 429
        if manager_id_input and not email:
            resolved_email, _uid = _find_user_email_by_manager_id(manager_id_input)
            if not resolved_email:
                _record_login_attempt(login_key)
                return jsonify({"message": "Manager ID not found. Use email once to bootstrap this account."}), 404
            email = resolved_email

        if not email:
            _record_login_attempt(login_key)
            return jsonify({"message": "Manager ID or email is required"}), 400

        res = supabase.auth.sign_in_with_password({"email": email, "password": data.get("password")})
        manager_id = _manager_id_from_user_id(res.user.id)
        if manager_id_input and manager_id_input != manager_id:
            _record_login_attempt(login_key)
            return jsonify({"message": "Invalid Manager ID"}), 403
        _upsert_identity_record(user_id=res.user.id, email=res.user.email, manager_id=manager_id)
        _append_audit_log(
            event_type="manager_login",
            actor_id=res.user.id,
            actor_role="manager",
            details={"manager_id": manager_id, "email": res.user.email}
        )
        
        return jsonify({
            "token": res.session.access_token,
            "user": {
                "id": res.user.id,
                "email": res.user.email,
                "role": "admin",
                "manager_id": manager_id
            }
        }), 200
    except Exception as e:
        _record_login_attempt(f"admin::{(data.get('managerId') or data.get('email') or 'unknown')}")
        logger.error(f"Admin login error: {str(e)}")
        return jsonify({"message": str(e)}), 401


@app.route('/api/auth/employee/login', methods=['POST'])
def employee_login():
    """Employee login without access code"""
    data = request.json
    
    try:
        employee_id_input = (data.get("employeeId") or "").strip().upper()
        email = (data.get("email") or "").strip().lower()
        login_key = f"employee::{employee_id_input or email or 'unknown'}"
        if not _can_attempt_login(login_key):
            return jsonify({"message": "Too many login attempts. Please try again later."}), 429
        if employee_id_input:
            resolved_email, _uid = _find_user_email_by_employee_id(employee_id_input)
            if not resolved_email:
                _record_login_attempt(login_key)
                return jsonify({"message": "Employee ID not found"}), 404
            email = resolved_email

        if not email:
            _record_login_attempt(login_key)
            return jsonify({"message": "Employee ID is required"}), 400

        res = supabase.auth.sign_in_with_password({"email": email, "password": data.get("password")})
        employee_id = employee_id_input or _employee_id_from_user_id(res.user.id)
        _upsert_identity_record(user_id=res.user.id, email=res.user.email, employee_id=employee_id)
        row = supabase.table('user_settings').select("*").eq("user_id", res.user.id).limit(1).execute()
        status_meta = _identity_for_user(res.user.id) or (_parse_contact_meta(row.data[0].get("phone", "")) if row.data else {})
        if status_meta and status_meta.get("employment_status", "active") != "active":
            _record_login_attempt(login_key)
            return jsonify({"message": "Employee account is inactive. Contact your manager."}), 403
        _append_audit_log(
            event_type="employee_login",
            actor_id=res.user.id,
            actor_role="employee",
            details={"employee_id": employee_id, "email": res.user.email}
        )
        
        return jsonify({
            "token": res.session.access_token,
            "user": {
                "id": res.user.id,
                "email": res.user.email,
                "role": "employee",
                "employee_id": employee_id
            }
        }), 200
    except Exception as e:
        _record_login_attempt(f"employee::{(data.get('employeeId') or data.get('email') or 'unknown')}")
        logger.error(f"Employee login error: {str(e)}")
        return jsonify({"message": str(e)}), 401


# ==================== LEAVE REQUEST ENDPOINTS ====================

@app.route('/api/leave/apply', methods=['POST'])
def apply_leave():
    """Employee applies for leave"""
    try:
        data = request.json
        current_user, auth_error = _require_employee_auth()
        if auth_error:
            return auth_error
        if data.get("user_id") != current_user.id:
            return jsonify({"message": "Forbidden - user_id does not match token"}), 403
        user_row = supabase.table('user_settings').select("*").eq("user_id", current_user.id).limit(1).execute()
        meta = _identity_for_user(current_user.id) or (_parse_contact_meta(user_row.data[0].get("phone", "")) if user_row.data else {})
        if meta and meta.get("employment_status", "active") != "active":
            return jsonify({"message": "Inactive employee cannot apply for leave"}), 403
        
        logger.info(f"Processing leave application from user: {data.get('user_id')}")
        
        # Validate required fields
        required_fields = ['user_id', 'leave_type', 'start_date', 'end_date', 'reason']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        policy = _load_leave_policy()
        leave_type = data.get("leave_type")
        leave_rules = _get_leave_type_rules(leave_type)
        if not leave_rules:
            return jsonify({"message": f"Invalid leave_type: {leave_type}"}), 400
        requested_days = _requested_days(data.get("start_date"), data.get("end_date"))
        if requested_days <= 0:
            return jsonify({"message": "Invalid date range"}), 400
        if requested_days > int(leave_rules.get("max_consecutive_days", 0)):
            return jsonify({
                "message": f"{leave_type} cannot exceed {leave_rules.get('max_consecutive_days')} consecutive days"
            }), 400

        constraints = policy.get("constraints", {})
        blackout_dates = constraints.get("blackout_dates", [])
        if _date_range_has_blackout(data.get("start_date"), data.get("end_date"), blackout_dates):
            return jsonify({"message": "Selected dates include blackout date(s). Please choose different dates."}), 400

        department = data.get("department", "Not Specified")
        parallel_limit = int(constraints.get("max_parallel_leaves_per_department", 3))
        existing_rows = [r for r in _leave_select_all() if (r.get("department") or "Not Specified") == department]
        overlapping = 0
        for req in existing_rows:
            req_status = str(req.get("status", "")).lower()
            if not (req_status.startswith("pending") or req_status == "approved"):
                continue
            if _date_ranges_overlap(
                req.get("start_date", ""),
                req.get("end_date", ""),
                data.get("start_date", ""),
                data.get("end_date", "")
            ):
                overlapping += 1
        if overlapping >= parallel_limit:
            return jsonify({
                "message": f"Department leave capacity exceeded ({parallel_limit} concurrent leaves max)."
            }), 409
        
        # Prepare leave request data
        total_levels = _get_required_approval_levels()
        leave_data = {
            "id": str(uuid.uuid4()),
            "user_id": data.get("user_id"),
            "employee_name": data.get("employee_name", ""),
            "department": data.get("department", "Not Specified"),
            "leave_type": data.get("leave_type"),
            "start_date": data.get("start_date"),
            "end_date": data.get("end_date"),
            "reason": data.get("reason"),
            "status": _pending_status(1, total_levels),
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        proof_required = _proof_required_for_request(
            leave_data.get("leave_type", ""),
            leave_data.get("start_date", ""),
            leave_data.get("end_date", "")
        )
        
        logger.info(f"Leave data prepared: {leave_data}")
        
        # Insert into Supabase
        _leave_insert(leave_data)
        _set_proof_record(leave_data["id"], {
            "leave_request_id": leave_data["id"],
            "required": proof_required,
            "status": "not_submitted",
            "uploaded_by": "",
            "uploaded_at": "",
            "stored_name": "",
            "original_name": "",
            "reviewed_by": "",
            "reviewed_at": "",
            "review_note": ""
        })
        employee_settings = supabase.table('user_settings').select("*").eq("user_id", current_user.id).limit(1).execute()
        assigned_manager_id = ""
        if employee_settings.data:
            assigned_manager_id = employee_settings.data[0].get("profile_picture", "")
        manager_user_ids = _find_manager_user_ids_by_manager_id(assigned_manager_id) if assigned_manager_id else []

        _append_notification(
            recipient_user_id=current_user.id,
            title="Leave Request Submitted",
            message=f"Your {leave_data['leave_type']} leave request has been submitted.",
            kind="success",
            meta={"leave_request_id": leave_data["id"], "status": leave_data["status"]}
        )
        for manager_uid in manager_user_ids:
            _append_notification(
                recipient_user_id=manager_uid,
                title="New Leave Request",
                message=f"{leave_data.get('employee_name', 'Employee')} submitted {leave_data['leave_type']} leave.",
                kind="info",
                meta={"leave_request_id": leave_data["id"], "employee_user_id": current_user.id}
            )
        _append_audit_log(
            event_type="leave_applied",
            actor_id=current_user.id,
            actor_role="employee",
            details={
                "leave_request_id": leave_data["id"],
                "leave_type": leave_data["leave_type"],
                "start_date": leave_data["start_date"],
                "end_date": leave_data["end_date"]
            }
        )
        
        logger.info("Leave request inserted successfully")
        
        return jsonify({
            "message": "Leave application submitted successfully",
            "data": leave_data,
            "id": leave_data["id"],
            "proof_required": proof_required
        }), 201
        
    except Exception as e:
        logger.error(f"Error applying leave: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "message": f"Failed to submit application: {str(e)}",
            "error": str(e)
        }), 500


@app.route('/api/leave/requests', methods=['GET'])
def get_all_leave_requests():
    """Admin: Get all leave requests"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        employee_ids = _employee_ids_for_manager(manager_id)

        if not employee_ids:
            return jsonify({"data": [], "manager_id": manager_id}), 200

        result = _leave_select_all()
        filtered = [row for row in (result or []) if row.get("user_id") in employee_ids]
        filtered = _enrich_requests_with_proof(filtered)
        logger.info(f"Manager {manager_id} retrieved {len(filtered)} leave requests")
        return jsonify({"data": filtered, "manager_id": manager_id}), 200
    except Exception as e:
        logger.error(f"Error fetching leave requests: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/my-requests', methods=['GET'])
def get_employee_leave_requests():
    """Employee: Get their own leave requests"""
    try:
        current_user, auth_error = _require_employee_auth()
        if auth_error:
            return auth_error

        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({"message": "user_id parameter is required"}), 400
        if user_id != current_user.id:
            return jsonify({"message": "Forbidden - user_id does not match token"}), 403
        
        logger.info(f"Fetching leave requests for user: {user_id}")
        
        result = _leave_select_by_user(user_id)
        
        logger.info(f"Retrieved {len(result)} leave requests for user {user_id}")
        
        return jsonify({"data": _enrich_requests_with_proof(result)}), 200
    except Exception as e:
        logger.error(f"Error fetching employee leave requests: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/my-tracker', methods=['GET'])
def get_employee_leave_tracker():
    """Employee: Get leave tracker summary by type for current year"""
    try:
        current_user, auth_error = _require_employee_auth()
        if auth_error:
            return auth_error

        year = datetime.now().year
        user_id = request.args.get('user_id')
        if user_id and user_id != current_user.id:
            return jsonify({"message": "Forbidden - user_id does not match token"}), 403

        result = _leave_select_by_user(current_user.id)
        tracker = _build_tracker_from_requests(result or [], year)

        return jsonify({
            "data": tracker,
            "user_id": current_user.id
        }), 200
    except Exception as e:
        logger.error(f"Error fetching employee leave tracker: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/approve/<request_id>', methods=['POST'])
def approve_leave_request(request_id):
    """Admin: Approve a leave request"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        employee_ids = _employee_ids_for_manager(manager_id)

        target_row = _leave_select_by_id(request_id)
        if not target_row:
            return jsonify({"message": "Leave request not found"}), 404
        if target_row.get("user_id") not in employee_ids:
            return jsonify({"message": "Forbidden - request not assigned to your team"}), 403

        logger.info(f"Approving leave request: {request_id}")
        
        current_status = target_row.get("status", "")
        parsed = _parse_pending_status(current_status)
        if not parsed:
            return jsonify({"message": f"Request is not pending for approval (status: {current_status})"}), 400
        current_level, total_levels = parsed
        if current_level >= total_levels:
            required = _proof_required_for_request(
                target_row.get("leave_type", ""),
                target_row.get("start_date", ""),
                target_row.get("end_date", "")
            )
            proof = _get_proof_record(request_id) or {}
            if required and proof.get("status") != "verified":
                return jsonify({"message": "Proof document verification is required before final approval"}), 409

        update_payload = {"updated_at": datetime.now().isoformat()}
        if current_level < total_levels:
            update_payload["status"] = _pending_status(current_level + 1, total_levels)
            message = f"Leave request moved to approval level {current_level + 1} of {total_levels}"
        else:
            update_payload["status"] = "approved"
            update_payload["approved_at"] = datetime.now().isoformat()
            message = "Leave request fully approved"

        result = _leave_update_by_id(request_id, update_payload)
        target_user_id = target_row.get("user_id")
        if target_user_id:
            _append_notification(
                recipient_user_id=target_user_id,
                title="Leave Request Updated",
                message=message,
                kind="info",
                meta={"leave_request_id": request_id, "status": update_payload.get("status")}
            )
        _append_audit_log(
            event_type="leave_approved_step",
            actor_id=manager_user.id,
            actor_role="manager",
            details={
                "leave_request_id": request_id,
                "new_status": update_payload.get("status"),
                "department_scope": manager_id
            }
        )
        
        if not result:
            return jsonify({"message": "Leave request not found"}), 404
        
        logger.info(f"Leave request approved: {request_id}")
        
        return jsonify({
            "message": message,
            "data": result
        }), 200
    except Exception as e:
        logger.error(f"Error approving leave request: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/decline/<request_id>', methods=['POST'])
def decline_leave_request(request_id):
    """Admin: Decline a leave request"""
    try:
        data = request.json or {}
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        employee_ids = _employee_ids_for_manager(manager_id)

        target_row = _leave_select_by_id(request_id)
        if not target_row:
            return jsonify({"message": "Leave request not found"}), 404
        if target_row.get("user_id") not in employee_ids:
            return jsonify({"message": "Forbidden - request not assigned to your team"}), 403
        
        logger.info(f"Declining leave request: {request_id}")
        
        result = _leave_update_by_id(request_id, {
            "status": "declined",
            "decline_reason": data.get("reason", ""),
            "declined_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        })
        target_user_id = target_row.get("user_id")
        if target_user_id:
            _append_notification(
                recipient_user_id=target_user_id,
                title="Leave Request Declined",
                message=f"Your leave request was declined. Reason: {data.get('reason', 'Not provided')}",
                kind="warning",
                meta={"leave_request_id": request_id, "status": "declined"}
            )
        _append_audit_log(
            event_type="leave_declined",
            actor_id=manager_user.id,
            actor_role="manager",
            details={
                "leave_request_id": request_id,
                "reason": data.get("reason", "")
            }
        )
        
        if not result:
            return jsonify({"message": "Leave request not found"}), 404
        
        logger.info(f"Leave request declined: {request_id}")
        
        return jsonify({
            "message": "Leave request declined",
            "data": result
        }), 200
    except Exception as e:
        logger.error(f"Error declining leave request: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/proof/upload/<request_id>', methods=['POST'])
def upload_leave_proof(request_id):
    """Employee: upload leave proof document for a request"""
    try:
        current_user, auth_error = _require_employee_auth()
        if auth_error:
            return auth_error

        row = _leave_select_by_id(request_id)
        if not row:
            return jsonify({"message": "Leave request not found"}), 404
        if row.get("user_id") != current_user.id:
            return jsonify({"message": "Forbidden - not your leave request"}), 403

        if "file" not in request.files:
            return jsonify({"message": "file is required"}), 400
        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"message": "No file selected"}), 400

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_PROOF_EXTENSIONS:
            return jsonify({"message": "Unsupported file type. Use PDF/JPG/JPEG/PNG"}), 400
        file.seek(0, os.SEEK_END)
        size_bytes = file.tell()
        file.seek(0)
        if size_bytes > MAX_PROOF_FILE_SIZE_BYTES:
            return jsonify({"message": "File too large. Maximum allowed size is 5MB"}), 400

        os.makedirs(PROOF_UPLOAD_DIR, exist_ok=True)
        stored_name = f"{uuid.uuid4()}{ext}"
        file_path = os.path.join(PROOF_UPLOAD_DIR, stored_name)
        file.save(file_path)

        existing = _get_proof_record(request_id) or {}
        record = {
            "leave_request_id": request_id,
            "required": existing.get("required", _proof_required_for_request(
                row.get("leave_type", ""), row.get("start_date", ""), row.get("end_date", "")
            )),
            "status": "submitted",
            "uploaded_by": current_user.id,
            "uploaded_at": datetime.now().isoformat(),
            "stored_name": stored_name,
            "original_name": filename,
            "reviewed_by": "",
            "reviewed_at": "",
            "review_note": ""
        }
        _set_proof_record(request_id, record)

        employee_settings = supabase.table('user_settings').select("*").eq("user_id", current_user.id).limit(1).execute()
        assigned_manager_id = ""
        if employee_settings.data:
            assigned_manager_id = employee_settings.data[0].get("profile_picture", "")
        manager_user_ids = _find_manager_user_ids_by_manager_id(assigned_manager_id) if assigned_manager_id else []
        for manager_uid in manager_user_ids:
            _append_notification(
                recipient_user_id=manager_uid,
                title="Proof Document Submitted",
                message=f"Employee submitted proof for request {request_id}.",
                kind="info",
                meta={"leave_request_id": request_id, "proof_status": "submitted"}
            )

        _append_audit_log(
            event_type="leave_proof_uploaded",
            actor_id=current_user.id,
            actor_role="employee",
            details={"leave_request_id": request_id, "filename": filename}
        )
        return jsonify({"message": "Proof uploaded", "data": record}), 200
    except Exception as e:
        logger.error(f"Error uploading leave proof: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/proof/<request_id>', methods=['GET'])
def get_leave_proof_meta(request_id):
    """Owner/Manager: get proof metadata"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error

        row = _leave_select_by_id(request_id)
        if not row:
            return jsonify({"message": "Leave request not found"}), 404

        if row.get("user_id") != current_user.id:
            manager_id = _manager_id_from_user_id(current_user.id)
            team_ids = _employee_ids_for_manager(manager_id)
            if row.get("user_id") not in team_ids:
                return jsonify({"message": "Forbidden"}), 403

        proof = _get_proof_record(request_id)
        if not proof:
            return jsonify({"data": None}), 200
        return jsonify({"data": proof}), 200
    except Exception as e:
        logger.error(f"Error getting leave proof metadata: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/proof/file/<request_id>', methods=['GET'])
def download_leave_proof_file(request_id):
    """Owner/Manager: download proof file"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error

        row = _leave_select_by_id(request_id)
        if not row:
            return jsonify({"message": "Leave request not found"}), 404
        if row.get("user_id") != current_user.id:
            manager_id = _manager_id_from_user_id(current_user.id)
            team_ids = _employee_ids_for_manager(manager_id)
            if row.get("user_id") not in team_ids:
                return jsonify({"message": "Forbidden"}), 403

        proof = _get_proof_record(request_id)
        if not proof or not proof.get("stored_name"):
            return jsonify({"message": "Proof file not found"}), 404
        return send_from_directory(PROOF_UPLOAD_DIR, proof["stored_name"], as_attachment=True, download_name=proof.get("original_name", "proof"))
    except Exception as e:
        logger.error(f"Error downloading proof file: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/proof/review/<request_id>', methods=['POST'])
def review_leave_proof(request_id):
    """Manager: verify or reject proof document"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        data = request.json or {}
        decision = (data.get("decision") or "").strip().lower()
        note = (data.get("note") or "").strip()
        if decision not in ["verified", "rejected"]:
            return jsonify({"message": "decision must be verified or rejected"}), 400

        row = _leave_select_by_id(request_id)
        if not row:
            return jsonify({"message": "Leave request not found"}), 404
        if row.get("user_id") not in _employee_ids_for_manager(manager_id):
            return jsonify({"message": "Forbidden - request not assigned to your team"}), 403

        proof = _get_proof_record(request_id)
        if not proof or proof.get("status") == "not_submitted":
            return jsonify({"message": "No submitted proof found"}), 404

        proof["status"] = decision
        proof["reviewed_by"] = manager_user.id
        proof["reviewed_at"] = datetime.now().isoformat()
        proof["review_note"] = note
        _set_proof_record(request_id, proof)

        _append_notification(
            recipient_user_id=row.get("user_id"),
            title="Proof Review Update",
            message=f"Your proof document was {decision}. {note}".strip(),
            kind="info",
            meta={"leave_request_id": request_id, "proof_status": decision}
        )
        _append_audit_log(
            event_type="leave_proof_reviewed",
            actor_id=manager_user.id,
            actor_role="manager",
            details={"leave_request_id": request_id, "decision": decision, "note": note}
        )
        return jsonify({"message": "Proof reviewed", "data": proof}), 200
    except Exception as e:
        logger.error(f"Error reviewing proof: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/employees', methods=['GET'])
def get_manager_employees():
    """Admin/Manager: Get employees assigned to this manager"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error

        employees = []
        try:
            rows = supabase.table('user_settings').select("*").eq("profile_picture", manager_id).execute()
            for row in (rows.data or []):
                meta = _identity_for_user(row.get("user_id")) or _parse_contact_meta(row.get("phone", ""))
                employees.append({
                    "user_id": row.get("user_id"),
                    "employee_id": meta.get("employee_id") or _employee_id_from_user_id(row.get("user_id", "")),
                    "full_name": row.get("full_name") or meta.get("full_name") or "Unnamed Employee",
                    "email": meta.get("email") or "",
                    "department": row.get("department") or meta.get("department") or "Not Specified",
                    "status": meta.get("employment_status", "active")
                })
        except Exception as e:
            logger.warning(f"user_settings read skipped due to RLS/permission: {str(e)}")

        if not employees:
            identity_map = _load_identity_map().get("by_user_id", {})
            for uid, meta in identity_map.items():
                if meta.get("manager_id") != manager_id or not meta.get("employee_id"):
                    continue
                employees.append({
                    "user_id": uid,
                    "employee_id": meta.get("employee_id"),
                    "full_name": meta.get("full_name") or "Unnamed Employee",
                    "email": meta.get("email") or "",
                    "department": meta.get("department") or "Not Specified",
                    "status": meta.get("employment_status", "active")
                })

        return jsonify({"data": employees, "manager_id": manager_id}), 200
    except Exception as e:
        logger.error(f"Error fetching manager employees: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/employees/leave-tracker', methods=['GET'])
def get_manager_employee_leave_tracker():
    """Admin/Manager: Leave tracker summary for each assigned employee"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error

        employee_ids = _employee_ids_for_manager(manager_id)
        if not employee_ids:
            return jsonify({"data": [], "manager_id": manager_id, "year": datetime.now().year}), 200

        settings_by_user = {}
        try:
            settings_rows = supabase.table('user_settings').select("*").eq("profile_picture", manager_id).execute()
            settings_by_user = {row.get("user_id"): row for row in (settings_rows.data or [])}
        except Exception as e:
            logger.warning(f"user_settings read skipped due to RLS/permission: {str(e)}")

        grouped = {}
        for req in (_leave_select_all() or []):
            uid = req.get("user_id")
            if uid in employee_ids:
                grouped.setdefault(uid, []).append(req)

        year = datetime.now().year
        output = []
        for uid in employee_ids:
            tracker = _build_tracker_from_requests(grouped.get(uid, []), year)
            total_quota = sum(v["quota"] for v in tracker["by_type"].values())
            total_approved = sum(v["approved_days"] for v in tracker["by_type"].values())
            total_pending = sum(v["pending_days"] for v in tracker["by_type"].values())
            total_remaining = max(total_quota - total_approved, 0)
            profile = settings_by_user.get(uid, {})
            meta = _identity_for_user(uid) or _parse_contact_meta(profile.get("phone", ""))
            output.append({
                "user_id": uid,
                "employee_id": meta.get("employee_id") or _employee_id_from_user_id(uid),
                "employee_name": profile.get("full_name") or meta.get("full_name") or "Unnamed Employee",
                "email": meta.get("email") or "",
                "department": profile.get("department") or meta.get("department") or "Not Specified",
                "status": meta.get("employment_status", "active"),
                "totals": {
                    "quota_days": total_quota,
                    "approved_days": total_approved,
                    "pending_days": total_pending,
                    "remaining_days": total_remaining
                },
                "by_type": tracker["by_type"]
            })

        return jsonify({"data": output, "manager_id": manager_id, "year": year}), 200
    except Exception as e:
        logger.error(f"Error fetching manager leave tracker: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/employees/create', methods=['POST'])
def create_employee_for_manager():
    """Admin/Manager: Create an employee and assign to this manager"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error

        data = request.json or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        full_name = (data.get("full_name") or "").strip()
        department = (data.get("department") or "").strip()
        employee_id = (data.get("employee_id") or "").strip().upper()

        if not email or not password:
            return jsonify({"message": "email and password are required"}), 400
        if len(password) < 8:
            return jsonify({"message": "password must be at least 8 characters"}), 400
        if not employee_id.startswith("EMP-"):
            return jsonify({"message": "employee_id must start with EMP-"}), 400
        existing_email, existing_uid = _find_user_email_by_employee_id(employee_id)
        if existing_uid:
            return jsonify({"message": "employee_id already exists"}), 409

        signup = None
        user_id = None
        try:
            signup = supabase.auth.sign_up({"email": email, "password": password})
            if signup and signup.user:
                user_id = signup.user.id
        except Exception as e:
            # If user already exists, attempt to link by signing in with provided password.
            err_text = str(e).lower()
            if "already" in err_text and "registered" in err_text:
                try:
                    existing = supabase.auth.sign_in_with_password({"email": email, "password": password})
                    if existing and existing.user:
                        user_id = existing.user.id
                except Exception:
                    return jsonify({
                        "message": "User already registered. Provide the correct existing password to link this employee."
                    }), 409
            else:
                raise

        if not user_id:
            return jsonify({"message": "Failed to create or link employee account"}), 400

        settings_data = {
            "user_id": user_id,
            "full_name": full_name or email.split("@")[0],
            "phone": "",
            "department": department or "Not Specified",
            "profile_picture": manager_id,
            "updated_at": datetime.now().isoformat()
        }
        try:
            supabase.table('user_settings').insert(settings_data).execute()
        except Exception as e:
            logger.warning(f"user_settings insert skipped due to RLS/permission: {str(e)}")
        _record_identity(
            user_id=user_id,
            email=email,
            manager_id=manager_id,
            employee_id=employee_id,
            employment_status="active",
            full_name=settings_data["full_name"],
            department=settings_data["department"]
        )
        _append_audit_log(
            event_type="employee_created",
            actor_id=manager_user.id,
            actor_role="manager",
            details={
                "employee_user_id": signup.user.id,
                "employee_id": employee_id,
                "employee_email": email,
                "assigned_manager_id": manager_id
            }
        )

        return jsonify({
            "message": "Employee created and assigned successfully",
            "data": {
                "user_id": user_id,
                "employee_id": employee_id,
                "email": email,
                "full_name": settings_data["full_name"],
                "department": settings_data["department"],
                "assigned_manager_id": manager_id
            }
        }), 201
    except Exception as e:
        logger.error(f"Error creating employee: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/employees/<employee_id>/status', methods=['PATCH'])
def update_employee_status(employee_id):
    """Admin/Manager: Activate or deactivate employee"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        data = request.json or {}
        new_status = (data.get("status") or "").strip().lower()
        if new_status not in ["active", "inactive"]:
            return jsonify({"message": "status must be active or inactive"}), 400

        row, meta = _find_user_setting_by_employee_id(employee_id.strip().upper())
        if not row:
            return jsonify({"message": "Employee not found"}), 404
        if row.get("profile_picture") != manager_id:
            return jsonify({"message": "Forbidden - employee not in your team"}), 403

        _record_identity(
            user_id=row.get("user_id"),
            email=(meta or {}).get("email", ""),
            manager_id=(meta or {}).get("manager_id", ""),
            employee_id=(meta or {}).get("employee_id", employee_id),
            employment_status=new_status
        )
        supabase.table('user_settings').update({
            "updated_at": datetime.now().isoformat()
        }).eq("user_id", row.get("user_id")).execute()

        _append_audit_log(
            event_type="employee_status_updated",
            actor_id=manager_user.id,
            actor_role="manager",
            details={"employee_id": employee_id, "new_status": new_status}
        )
        return jsonify({"message": "Employee status updated", "employee_id": employee_id, "status": new_status}), 200
    except Exception as e:
        logger.error(f"Error updating employee status: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/employees/<employee_id>/reassign', methods=['PATCH'])
def reassign_employee_manager(employee_id):
    """Admin/Manager: Reassign employee to another manager ID"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        data = request.json or {}
        new_manager_id = (data.get("manager_id") or "").strip().upper()
        if not new_manager_id.startswith("MGR-"):
            return jsonify({"message": "manager_id must start with MGR-"}), 400

        row, meta = _find_user_setting_by_employee_id(employee_id.strip().upper())
        if not row:
            return jsonify({"message": "Employee not found"}), 404
        if row.get("profile_picture") != manager_id:
            return jsonify({"message": "Forbidden - employee not in your team"}), 403

        _record_identity(
            user_id=row.get("user_id"),
            email=(meta or {}).get("email", ""),
            manager_id=new_manager_id,
            employee_id=(meta or {}).get("employee_id", employee_id),
            employment_status=(meta or {}).get("employment_status", "active")
        )
        supabase.table('user_settings').update({
            "profile_picture": new_manager_id,
            "updated_at": datetime.now().isoformat()
        }).eq("user_id", row.get("user_id")).execute()

        _append_audit_log(
            event_type="employee_reassigned",
            actor_id=manager_user.id,
            actor_role="manager",
            details={"employee_id": employee_id, "from_manager_id": manager_id, "to_manager_id": new_manager_id}
        )
        return jsonify({"message": "Employee reassigned", "employee_id": employee_id, "manager_id": new_manager_id}), 200
    except Exception as e:
        logger.error(f"Error reassigning employee: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/policy', methods=['GET'])
def get_leave_policy():
    """Admin/Manager: Get current leave policy"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        policy = _load_leave_policy()
        return jsonify({"data": policy, "manager_id": manager_id}), 200
    except Exception as e:
        logger.error(f"Error fetching leave policy: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/policy', methods=['PUT'])
def update_leave_policy():
    """Admin/Manager: Update leave policy"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        data = request.json or {}
        validation_error = _validate_leave_policy(data)
        if validation_error:
            return jsonify({"message": validation_error}), 400
        if "version" not in data:
            data["version"] = 1
        _save_leave_policy(data)
        _append_audit_log(
            event_type="policy_updated",
            actor_id=manager_user.id,
            actor_role="manager",
            details={"version": data.get("version"), "approval_levels": data.get("workflow", {}).get("approval_levels")}
        )
        return jsonify({"message": "Leave policy updated", "data": data}), 200
    except Exception as e:
        logger.error(f"Error updating leave policy: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/audit', methods=['GET'])
def get_audit_logs():
    """Admin/Manager: Read audit logs"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        limit = request.args.get("limit", "200")
        try:
            parsed_limit = int(limit)
        except ValueError:
            parsed_limit = 200
        data = _read_audit_logs(parsed_limit)
        return jsonify({"data": data, "manager_id": manager_id}), 200
    except Exception as e:
        logger.error(f"Error fetching audit logs: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/admin/analytics', methods=['GET'])
def get_admin_analytics():
    """Admin/Manager: analytics summary for reports"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error

        requests_data = _manager_scoped_requests(manager_id)
        year = datetime.now().year
        monthly = {str(m).zfill(2): {"approved": 0, "pending": 0, "declined": 0} for m in range(1, 13)}
        by_department = {}
        by_leave_type = {}
        by_employee = {}
        approval_durations = []

        for req in requests_data:
            status = str(req.get("status", "")).lower()
            dept = req.get("department") or "Not Specified"
            leave_type = req.get("leave_type") or "Unknown"
            user_id = req.get("user_id") or ""
            employee_name = req.get("employee_name") or "Unnamed Employee"

            start_dt = _safe_date(req.get("start_date", ""))
            if start_dt and start_dt.year == year:
                month_key = str(start_dt.month).zfill(2)
                if status.startswith("pending"):
                    monthly[month_key]["pending"] += 1
                elif status == "approved":
                    monthly[month_key]["approved"] += 1
                elif status == "declined":
                    monthly[month_key]["declined"] += 1

            by_department.setdefault(dept, {"total": 0, "approved": 0, "pending": 0, "declined": 0})
            by_department[dept]["total"] += 1
            if status.startswith("pending"):
                by_department[dept]["pending"] += 1
            elif status == "approved":
                by_department[dept]["approved"] += 1
            elif status == "declined":
                by_department[dept]["declined"] += 1

            by_leave_type.setdefault(leave_type, {"total": 0, "approved": 0, "pending": 0, "declined": 0})
            by_leave_type[leave_type]["total"] += 1
            if status.startswith("pending"):
                by_leave_type[leave_type]["pending"] += 1
            elif status == "approved":
                by_leave_type[leave_type]["approved"] += 1
            elif status == "declined":
                by_leave_type[leave_type]["declined"] += 1

            by_employee.setdefault(user_id, {
                "user_id": user_id,
                "employee_name": employee_name,
                "approved_days": 0,
                "pending_days": 0,
                "declined_days": 0
            })
            days = _requested_days(req.get("start_date", ""), req.get("end_date", ""))
            if status == "approved":
                by_employee[user_id]["approved_days"] += days
            elif status.startswith("pending"):
                by_employee[user_id]["pending_days"] += days
            elif status == "declined":
                by_employee[user_id]["declined_days"] += days

            created = req.get("created_at")
            approved = req.get("approved_at")
            if status == "approved" and created and approved:
                try:
                    c_dt = datetime.fromisoformat(created)
                    a_dt = datetime.fromisoformat(approved)
                    diff_hours = max((a_dt - c_dt).total_seconds() / 3600.0, 0)
                    approval_durations.append(diff_hours)
                except Exception:
                    pass

        total = len(requests_data)
        approved_count = len([r for r in requests_data if str(r.get("status", "")).lower() == "approved"])
        pending_count = len([r for r in requests_data if str(r.get("status", "")).lower().startswith("pending")])
        declined_count = len([r for r in requests_data if str(r.get("status", "")).lower() == "declined"])
        approval_rate = round((approved_count / total) * 100, 2) if total else 0.0
        avg_approval_hours = round(sum(approval_durations) / len(approval_durations), 2) if approval_durations else 0.0

        top_absent = sorted(by_employee.values(), key=lambda x: x["approved_days"], reverse=True)[:10]

        return jsonify({
            "data": {
                "summary": {
                    "total_requests": total,
                    "approved": approved_count,
                    "pending": pending_count,
                    "declined": declined_count,
                    "approval_rate_percent": approval_rate,
                    "avg_approval_time_hours": avg_approval_hours
                },
                "monthly_trend": monthly,
                "by_department": by_department,
                "by_leave_type": by_leave_type,
                "top_absent_employees": top_absent
            },
            "manager_id": manager_id,
            "year": year
        }), 200
    except Exception as e:
        logger.error(f"Error fetching analytics: {str(e)}")
        return jsonify({"message": str(e)}), 500


# ==================== SETTINGS ENDPOINTS ====================

@app.route('/api/settings/profile', methods=['GET'])
def get_profile_settings():
    """Get user profile settings"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({"message": "user_id parameter is required"}), 400
        if user_id != current_user.id:
            return jsonify({"message": "Forbidden - cannot access another user's settings"}), 403
        
        result = supabase.table('user_settings').select("*").eq("user_id", user_id).execute()
        
        if result.data:
            item = result.data[0]
            meta = _identity_for_user(user_id) or _parse_contact_meta(item.get("phone", ""))
            item["assigned_manager_id"] = item.get("profile_picture", "")
            item["manager_id"] = _manager_id_from_user_id(user_id)
            item["employee_id"] = meta.get("employee_id") or _employee_id_from_user_id(user_id)
            item["phone"] = meta.get("phone", "")
            item["email"] = meta.get("email", "")
            return jsonify({"data": item}), 200
        return jsonify({"data": None}), 200
    except Exception as e:
        logger.error(f"Error fetching profile settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/settings/profile', methods=['PUT'])
def update_profile_settings():
    """Update user profile settings"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        data = request.json
        user_id = data.get("user_id")
        
        if not user_id:
            return jsonify({"message": "user_id is required"}), 400
        if user_id != current_user.id:
            return jsonify({"message": "Forbidden - cannot update another user's settings"}), 403
        
        existing = supabase.table('user_settings').select("*").eq("user_id", user_id).limit(1).execute()
        old = existing.data[0] if existing.data else {}
        old_meta = _identity_for_user(user_id) or _parse_contact_meta(old.get("phone", ""))
        settings_data = {
            "user_id": user_id,
            "full_name": data.get("full_name", ""),
            "phone": (data.get("phone", old.get("phone", "")) or "")[:20],
            "department": data.get("department", ""),
            # Reused as assigned_manager_id in this version.
            "profile_picture": data.get("assigned_manager_id", old.get("profile_picture", "")),
            "updated_at": datetime.now().isoformat()
        }
        _record_identity(
            user_id=user_id,
            email=old_meta.get("email", ""),
            manager_id=old_meta.get("manager_id", ""),
            employee_id=old_meta.get("employee_id", ""),
            employment_status=old_meta.get("employment_status", "active")
        )
        
        # Try to update first, if no rows affected, insert new
        result = supabase.table('user_settings').update(settings_data).eq("user_id", user_id).execute()
        
        if not result.data:
            # If update didn't work, insert instead
            result = supabase.table('user_settings').insert(settings_data).execute()
        
        return jsonify({
            "message": "Settings updated successfully",
            "data": settings_data
        }), 200
    except Exception as e:
        logger.error(f"Error updating profile settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/settings/notifications', methods=['GET'])
def get_notification_settings():
    """Get notification preferences"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({"message": "user_id parameter is required"}), 400
        if user_id != current_user.id:
            return jsonify({"message": "Forbidden - cannot access another user's notification settings"}), 403
        
        result = supabase.table('notification_settings').select("*").eq("user_id", user_id).execute()
        
        if result.data:
            return jsonify({"data": result.data[0]}), 200
        return jsonify({"data": None}), 200
    except Exception as e:
        logger.error(f"Error fetching notification settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/settings/notifications', methods=['PUT'])
def update_notification_settings():
    """Update notification preferences"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        data = request.json
        user_id = data.get("user_id")
        
        if not user_id:
            return jsonify({"message": "user_id is required"}), 400
        if user_id != current_user.id:
            return jsonify({"message": "Forbidden - cannot update another user's notification settings"}), 403
        
        settings_data = {
            "user_id": user_id,
            "email_notifications": data.get("email_notifications", True),
            "sms_notifications": data.get("sms_notifications", False),
            "in_app_notifications": data.get("in_app_notifications", True),
            "updated_at": datetime.now().isoformat()
        }
        
        result = supabase.table('notification_settings').update(settings_data).eq("user_id", user_id).execute()
        
        if not result.data:
            result = supabase.table('notification_settings').insert(settings_data).execute()
        
        return jsonify({
            "message": "Notification settings updated",
            "data": settings_data
        }), 200
    except Exception as e:
        logger.error(f"Error updating notification settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    """Get in-app notifications for current user"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        limit = request.args.get("limit", "50")
        try:
            parsed_limit = int(limit)
        except ValueError:
            parsed_limit = 50
        data = _read_notifications_for_user(current_user.id, parsed_limit)
        unread_count = sum(1 for item in data if not item.get("read"))
        return jsonify({"data": data, "unread_count": unread_count}), 200
    except Exception as e:
        logger.error(f"Error getting notifications: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/notifications/read/<notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    """Mark a single notification as read"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        if not os.path.exists(NOTIFICATION_FILE):
            return jsonify({"message": "Notification not found"}), 404

        updated = False
        rewritten = []
        with open(NOTIFICATION_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if item.get("id") == notification_id and item.get("recipient_user_id") == current_user.id:
                    item["read"] = True
                    updated = True
                rewritten.append(item)
        if not updated:
            return jsonify({"message": "Notification not found"}), 404
        _rewrite_notification_file(rewritten)
        return jsonify({"message": "Notification marked as read"}), 200
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/notifications/read-all', methods=['POST'])
def mark_all_notifications_read():
    """Mark all notifications for current user as read"""
    try:
        current_user, auth_error = _require_auth_user()
        if auth_error:
            return auth_error
        if not os.path.exists(NOTIFICATION_FILE):
            return jsonify({"message": "No notifications"}), 200

        rewritten = []
        with open(NOTIFICATION_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if item.get("recipient_user_id") == current_user.id:
                    item["read"] = True
                rewritten.append(item)
        _rewrite_notification_file(rewritten)
        return jsonify({"message": "All notifications marked as read"}), 200
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {str(e)}")
        return jsonify({"message": str(e)}), 500


# ==================== DASHBOARD STATS ENDPOINTS ====================

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        manager_user, manager_id, auth_error = _require_manager_auth()
        if auth_error:
            return auth_error
        data = _manager_scoped_requests(manager_id)
        
        stats = {
            "total_pending": len([r for r in data if str(r.get('status', '')).lower().startswith('pending')]),
            "total_approved": len([r for r in data if r.get('status') == 'approved']),
            "total_declined": len([r for r in data if r.get('status') == 'declined']),
            "on_leave_today": 0
        }
        
        return jsonify({"data": stats}), 200
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {str(e)}")
        return jsonify({"message": str(e)}), 500


# ==================== HEALTH CHECK ====================

@app.route('/', methods=['GET'])
def root():
    """Serve the login page so the app works from a single Flask server"""
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/index.html', methods=['GET'])
def index_page():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/admin-dashboard.html', methods=['GET'])
def admin_dashboard_page():
    return send_from_directory(BASE_DIR, 'admin-dashboard.html')


@app.route('/employee-dashboard.html', methods=['GET'])
def employee_dashboard_page():
    return send_from_directory(BASE_DIR, 'employee-dashboard.html')


@app.route('/styles.css', methods=['GET'])
def styles_file():
    return send_from_directory(BASE_DIR, 'styles.css')


@app.route('/script.js', methods=['GET'])
def script_file():
    return send_from_directory(BASE_DIR, 'script.js')


@app.route('/dashboard.js', methods=['GET'])
def dashboard_file():
    return send_from_directory(BASE_DIR, 'dashboard.js')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test leave data access with RLS-safe fallback
        _leave_select_all()
        return jsonify({
            "status": "healthy",
            "leave_store": "available"
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"message": "Internal server error"}), 500


if __name__ == '__main__':
    print("=" * 50)
    print("LeaveFlow Backend Server Starting")
    print("=" * 50)
    print(f"Supabase URL: {url[:50]}...")
    print("App URL: http://127.0.0.1:5000")
    print("Health Check: http://127.0.0.1:5000/api/health")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
