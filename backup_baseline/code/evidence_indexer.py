"""Evidence indexer for Ghost Data Still Exists.
Parses manifests, JSON snapshot bundles, SQL database dumps, log files (both text and JSON lines),
text handovers, PDF attachments, and operational activity streams into a unified queryable evidence index.
"""

import csv
import glob
import json
import os
import re
import sqlite3
import subprocess
from typing import Any, Dict, List, Optional, Set
from code.models import ResourceObservation


IDENTIFIER_KEYS = [
    "user_id",
    "email",
    "phone",
    "customer_reference",
    "subject_reference",
    "lookup_key",
    "customer_email",
    "customer_phone",
    "owner_email",
    "owner_phone",
    "requester_email",
    "requester_phone",
    "subject_selector",
    "correlation_key",
    "subject_ref",
    "subject_key",
    "match_key",
    "scan_key",
    "matched_value",
    "query",
]


class EvidenceIndexer:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.evidence_dir = os.path.join(dataset_dir, "evidence")
        self.manifest_by_file_id: Dict[str, Dict[str, str]] = {}
        self.manifest_by_path: Dict[str, Dict[str, str]] = {}
        self.observations: List[ResourceObservation] = []
        self.observations_by_resource: Dict[str, List[ResourceObservation]] = {}
        self.observations_by_ident: Dict[str, List[ResourceObservation]] = {}

        self._load_manifest()
        self._load_json_evidence()
        self._load_sql_evidence()
        self._load_log_evidence()
        self._load_text_evidence()
        self._load_pdf_evidence()
        self._load_system_activity()
        self._build_indices()

    def _normalize_ident(self, val: Optional[str]) -> Optional[str]:
        if not val:
            return None
        val_str = str(val).strip().lower()
        if val_str in ("null", "none", "", "undefined"):
            return None
        return val_str

    def _load_manifest(self):
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        if not os.path.exists(manifest_path):
            return
        with open(manifest_path, mode="r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                fid = row["file_id"].strip()
                fpath = row["file_path"].strip()
                norm_rel = os.path.normpath(fpath)
                item = {
                    "file_id": fid,
                    "file_path": fpath,
                    "origin": row.get("origin", "").strip(),
                    "captured_at": row.get("captured_at", "").strip(),
                }
                self.manifest_by_file_id[fid] = item
                self.manifest_by_path[norm_rel] = item
                if norm_rel.startswith("evidence/"):
                    self.manifest_by_path[norm_rel[len("evidence/"):]] = item

    def _get_file_metadata(self, full_path: str) -> Dict[str, str]:
        rel = os.path.relpath(full_path, self.dataset_dir)
        norm_rel = os.path.normpath(rel)
        if norm_rel in self.manifest_by_path:
            return self.manifest_by_path[norm_rel]
        base = os.path.basename(full_path)
        for p, meta in self.manifest_by_path.items():
            if os.path.basename(p) == base:
                return meta
        return {"file_id": "unknown", "origin": "unknown", "captured_at": "1970-01-01T00:00:00Z"}

    def _add_observation(
        self,
        resource_id: str,
        system_id: str,
        category: str,
        state: str,
        observed_at: str,
        file_id: str,
        origin: str,
        identifiers: Set[str],
        raw_record: Optional[Dict[str, Any]] = None,
    ):
        if not resource_id:
            return
        clean_idents = {self._normalize_ident(i) for i in identifiers if self._normalize_ident(i)}
        obs = ResourceObservation(
            resource_id=resource_id.strip(),
            system_id=system_id.strip(),
            category=category.strip(),
            state=state.strip(),
            observed_at=observed_at.strip(),
            file_id=file_id.strip(),
            origin=origin.strip(),
            identifiers=clean_idents,
            raw_record=raw_record or {},
        )
        self.observations.append(obs)

    def _load_json_evidence(self):
        json_pattern = os.path.join(self.evidence_dir, "**", "*.json")
        for path in glob.glob(json_pattern, recursive=True):
            meta = self._get_file_metadata(path)
            fid = meta["file_id"]
            origin = meta["origin"]
            cap_at = meta["captured_at"]

            try:
                with open(path, mode="r", encoding="utf-8") as f:
                    data = json.load(f)

                if "snapshots" in data:
                    for snap in data["snapshots"]:
                        data_store = snap.get("data_store", "unknown")
                        collection = snap.get("collection", "")
                        snap_at = snap.get("captured_at", cap_at)

                        for rec in snap.get("records", []):
                            rid = rec.get("resource_id")
                            if not rid:
                                continue
                            idents = set()
                            for k in IDENTIFIER_KEYS:
                                if rec.get(k):
                                    idents.add(str(rec[k]))

                            doc = rec.get("document") or {}
                            if isinstance(doc, dict):
                                for k in ["customer_reference", "email", "display_name"]:
                                    if doc.get(k):
                                        idents.add(str(doc[k]))

                            sys_id = data_store
                            if rid.startswith("account_"):
                                sys_id = "account_service"
                                state = "PRESENT" if rec.get("account_status") != "DELETED" else "ABSENT"
                                cat = "USER_PROFILE"
                            elif rid.startswith("search_"):
                                sys_id = "search_service"
                                state = "PRESENT"
                                cat = "SEARCH_INDEX_ENTRY"
                            elif rid.startswith("support_"):
                                sys_id = "support_platform"
                                if "attachment" in collection or "attachment" in str(rec):
                                    state = "PRESENT"
                                    cat = "SUPPORT_ATTACHMENT"
                                else:
                                    has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("message_text"))
                                    state = "PRESENT" if has_pii else "REDACTED"
                                    cat = "SUPPORT_MESSAGE"
                            elif rid.startswith("analytics_"):
                                sys_id = "analytics_platform"
                                has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("user_id"))
                                state = "PRESENT" if has_pii else "ANONYMIZED"
                                cat = "ANALYTICS_PROFILE"
                            elif rid.startswith("data_flow_"):
                                sys_id = "integration_service"
                                state = "ACTIVE" if rec.get("enabled", True) else "DISABLED"
                                cat = "DATA_FLOW"
                            elif rid.startswith("backup_"):
                                sys_id = "backup_service"
                                state = "ACTIVE" if rec.get("restore_allowed", True) else "BLOCKED"
                                cat = "BACKUP_ARCHIVE"
                            elif rid.startswith("audit_record_"):
                                sys_id = "security_service"
                                state = "PRESENT"
                                cat = "SECURITY_AUDIT_LOG"
                            elif rid.startswith("tombstone_"):
                                sys_id = "identity_service"
                                has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                                state = "PRESENT" if has_pii else "REDACTED"
                                cat = "ACCOUNT_TOMBSTONE"
                            elif rid.startswith("export_"):
                                sys_id = "export_service"
                                state = "PRESENT"
                                cat = "USER_EXPORT"
                            else:
                                state = "PRESENT"
                                cat = "UNKNOWN"

                            self._add_observation(
                                resource_id=rid,
                                system_id=sys_id,
                                category=cat,
                                state=state,
                                observed_at=snap_at,
                                file_id=fid,
                                origin=origin,
                                identifiers=idents,
                                raw_record=rec,
                            )

                elif "service_exports" in data:
                    exp_at = data.get("exported_at", cap_at)
                    se = data["service_exports"]

                    for item in se.get("account_service", {}).get("profile_lookups", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        code = item.get("status_code", 404)
                        state = "ABSENT" if code == 404 else "PRESENT"
                        idents = set()
                        prof = item.get("profile") or {}
                        if isinstance(prof, dict):
                            for k in ["customer_reference", "email", "phone"]:
                                if prof.get(k):
                                    idents.add(str(prof[k]))
                        self._add_observation(
                            resource_id=rid,
                            system_id="account_service",
                            category="USER_PROFILE",
                            state=state,
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("analytics_platform", {}).get("profiles", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        for k in ["customer_reference", "email", "phone", "user_id"]:
                            if item.get(k):
                                idents.add(str(item[k]))
                        has_pii = bool(idents)
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                        self._add_observation(
                            resource_id=rid,
                            system_id="analytics_platform",
                            category="ANALYTICS_PROFILE",
                            state=state,
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("backup_service", {}).get("restore_entries", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        for k in ["customer_reference", "customer_email"]:
                            if item.get(k):
                                idents.add(str(item[k]))
                        state = "ACTIVE" if item.get("restore_allowed", False) else "BLOCKED"
                        self._add_observation(
                            resource_id=rid,
                            system_id="backup_service",
                            category="BACKUP_ARCHIVE",
                            state=state,
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("integration_service", {}).get("connectors", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        for k in ["customer_reference", "customer_email"]:
                            if item.get(k):
                                idents.add(str(item[k]))
                        state = "ACTIVE" if item.get("enabled", False) else "DISABLED"
                        self._add_observation(
                            resource_id=rid,
                            system_id="integration_service",
                            category="DATA_FLOW",
                            state=state,
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("search_service", {}).get("index_queries", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        if item.get("query"):
                            idents.add(str(item["query"]))
                        hits = item.get("hits", {})
                        total = hits.get("total", 0)
                        state = "PRESENT" if total > 0 else "ABSENT"
                        for doc in hits.get("documents", []):
                            for k in ["customer_reference", "email", "phone"]:
                                if doc.get(k):
                                    idents.add(str(doc[k]))
                        self._add_observation(
                            resource_id=rid,
                            system_id="search_service",
                            category="SEARCH_INDEX_ENTRY",
                            state=state,
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("security_service", {}).get("audit_records", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        if item.get("subject_reference"):
                            idents.add(str(item["subject_reference"]))
                        self._add_observation(
                            resource_id=rid,
                            system_id="security_service",
                            category="SECURITY_AUDIT_LOG",
                            state="PRESENT",
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("support_platform", {}).get("tickets", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        for k in ["customer_reference", "requester_email", "requester_phone"]:
                            if item.get(k):
                                idents.add(str(item[k]))
                        has_pii = bool(item.get("requester_email") or item.get("requester_phone"))
                        state = "PRESENT" if has_pii else "REDACTED"
                        self._add_observation(
                            resource_id=rid,
                            system_id="support_platform",
                            category="SUPPORT_MESSAGE",
                            state=state,
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                    for item in se.get("export_service", {}).get("exports", []):
                        rid = item.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        for k in ["customer_reference", "owner_email", "owner_phone"]:
                            if item.get(k):
                                idents.add(str(item[k]))
                        self._add_observation(
                            resource_id=rid,
                            system_id="export_service",
                            category="USER_EXPORT",
                            state="PRESENT",
                            observed_at=item.get("observed_at", exp_at),
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=item,
                        )

                elif "records" in data:
                    coll = data.get("collection", "")
                    cap = data.get("captured_at") or data.get("exported_at") or cap_at
                    for rec in data["records"]:
                        rid = rec.get("resource_id")
                        if not rid:
                            continue
                        idents = set()
                        for k in IDENTIFIER_KEYS:
                            if rec.get(k):
                                idents.add(str(rec[k]))

                        if rid.startswith("export_"):
                            sys_id = "export_service"
                            state = "PRESENT" if rec.get("download_available", True) else "ABSENT"
                            cat = "USER_EXPORT"
                        elif rid.startswith("audit_record_"):
                            sys_id = "security_service"
                            state = "PRESENT"
                            cat = "SECURITY_AUDIT_LOG"
                        elif rid.startswith("data_flow_"):
                            sys_id = "integration_service"
                            state = "ACTIVE" if rec.get("enabled", True) else "DISABLED"
                            cat = "DATA_FLOW"
                        elif rid.startswith("analytics_"):
                            sys_id = "analytics_platform"
                            has_pii = bool(rec.get("email") or rec.get("user_id"))
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                            cat = "ANALYTICS_PROFILE"
                        else:
                            sys_id = "unknown"
                            state = "PRESENT"
                            cat = "UNKNOWN"

                        self._add_observation(
                            resource_id=rid,
                            system_id=sys_id,
                            category=cat,
                            state=state,
                            observed_at=cap,
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=rec,
                        )
            except Exception:
                pass

    def _load_sql_evidence(self):
        sql_pattern = os.path.join(self.evidence_dir, "**", "*.sql")
        for path in glob.glob(sql_pattern, recursive=True):
            meta = self._get_file_metadata(path)
            fid = meta["file_id"]
            origin = meta["origin"]
            cap_at = meta["captured_at"]

            try:
                conn = sqlite3.connect(":memory:")
                with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
                    sql_text = f.read()
                conn.executescript(sql_text)
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = [r[0] for r in cur.fetchall()]

                for tbl in tables:
                    cur.execute(f"PRAGMA table_info({tbl});")
                    cols = [c[1] for c in cur.fetchall()]
                    cur.execute(f"SELECT * FROM {tbl};")
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        if not rid:
                            continue

                        idents = set()
                        for k in IDENTIFIER_KEYS:
                            if r_dict.get(k):
                                idents.add(str(r_dict[k]))

                        if "record_json" in r_dict:
                            try:
                                rj = json.loads(r_dict["record_json"])
                                for k, v in rj.items():
                                    if k not in r_dict or r_dict[k] is None:
                                        r_dict[k] = v
                                for k in IDENTIFIER_KEYS:
                                    if rj.get(k):
                                        idents.add(str(rj[k]))
                                if "document" in rj and isinstance(rj["document"], dict):
                                    for k in ["email", "customer_reference", "display_name"]:
                                        if rj["document"].get(k):
                                            idents.add(str(rj["document"][k]))
                                if "enabled" in rj:
                                    r_dict["enabled"] = rj["enabled"]
                                if "restore_allowed" in rj:
                                    r_dict["restore_allowed"] = rj["restore_allowed"]
                            except Exception:
                                pass

                        row_time = r_dict.get("updated_at") or r_dict.get("observed_at") or cap_at

                        if rid.startswith("account_"):
                            sys_id = "account_service"
                            cat = "USER_PROFILE"
                            # In failover replicas, check status
                            state = "PRESENT" if r_dict.get("account_status") != "DELETED" else "ABSENT"
                        elif rid.startswith("search_"):
                            sys_id = "search_service"
                            cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif rid.startswith("support_"):
                            sys_id = "support_platform"
                            cat = "SUPPORT_MESSAGE"
                            has_pii = bool(r_dict.get("requester_email") or r_dict.get("email"))
                            state = "PRESENT" if has_pii else "REDACTED"
                        elif rid.startswith("analytics_"):
                            sys_id = "analytics_platform"
                            cat = "ANALYTICS_PROFILE"
                            has_pii = bool(r_dict.get("email") or r_dict.get("user_id"))
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        elif rid.startswith("data_flow_"):
                            sys_id = "integration_service"
                            cat = "DATA_FLOW"
                            en = r_dict.get("enabled")
                            state = "ACTIVE" if en in (1, "1", True, "true") else "DISABLED"
                        elif rid.startswith("backup_"):
                            sys_id = "backup_service"
                            cat = "BACKUP_ARCHIVE"
                            ra = r_dict.get("restore_allowed")
                            state = "ACTIVE" if ra in (1, "1", True, "true") else "BLOCKED"
                        elif rid.startswith("audit_record_"):
                            sys_id = "security_service"
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif rid.startswith("export_"):
                            sys_id = "export_service"
                            cat = "USER_EXPORT"
                            state = "PRESENT"
                        elif rid.startswith("tombstone_"):
                            sys_id = "identity_service"
                            cat = "ACCOUNT_TOMBSTONE"
                            has_pii = bool(r_dict.get("name") or r_dict.get("email") or r_dict.get("phone"))
                            state = "PRESENT" if has_pii else "REDACTED"
                        else:
                            sys_id = "unknown"
                            cat = "UNKNOWN"
                            state = "PRESENT"

                        self._add_observation(
                            resource_id=rid,
                            system_id=sys_id,
                            category=cat,
                            state=state,
                            observed_at=row_time,
                            file_id=fid,
                            origin=origin,
                            identifiers=idents,
                            raw_record=r_dict,
                        )
                conn.close()
            except Exception:
                pass

    def _load_log_evidence(self):
        log_pattern = os.path.join(self.evidence_dir, "**", "*.log")
        for path in glob.glob(log_pattern, recursive=True):
            meta = self._get_file_metadata(path)
            fid = meta["file_id"]
            origin = meta["origin"]
            cap_at = meta["captured_at"]

            traces: Dict[str, Set[str]] = {}
            parsed_entries: List[Dict[str, Any]] = []

            try:
                with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        m_time = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
                        log_time = m_time.group(1) if m_time else cap_at
                        remainder = line[len(log_time):].strip() if m_time else line

                        is_json = False
                        entry_dict = {}
                        if remainder.startswith("{") and remainder.endswith("}"):
                            try:
                                entry_dict = json.loads(remainder)
                                is_json = True
                            except Exception:
                                is_json = False

                        if is_json:
                            trace_id = entry_dict.get("trace_id")
                            rid = entry_dict.get("resource_id")
                            sys_id = entry_dict.get("service") or entry_dict.get("logger")
                            event = entry_dict.get("event", "")
                            idents = set()
                            for k in IDENTIFIER_KEYS:
                                val = entry_dict.get(k)
                                if val and val != "null":
                                    idents.add(str(val))
                        else:
                            m_trace = re.search(r"(?:trace_id|requestId)=([a-zA-Z0-9_\-]+)", line)
                            trace_id = m_trace.group(1) if m_trace else None

                            m_rid = re.search(r"resource_id=([a-zA-Z0-9_]+)", line)
                            rid = m_rid.group(1) if m_rid else None

                            m_sys = re.search(r"service=([a-zA-Z0-9_]+)", line)
                            sys_id = m_sys.group(1) if m_sys else None

                            m_ev = re.search(r"event=([a-zA-Z0-9_]+)", line)
                            event = m_ev.group(1) if m_ev else ""

                            idents = set()
                            for k in IDENTIFIER_KEYS:
                                m_val = re.search(rf'{k}=[\"\']?([^ \"\'\n]+)', line)
                                if m_val:
                                    v = m_val.group(1)
                                    if v not in ("null", "none", ""):
                                        idents.add(v)

                        if trace_id and idents:
                            traces.setdefault(trace_id, set()).update(idents)

                        parsed_entries.append({
                            "line": line,
                            "time": log_time,
                            "trace_id": trace_id,
                            "rid": rid,
                            "sys_id": sys_id,
                            "event": event,
                            "idents": idents,
                            "json_dict": entry_dict if is_json else None,
                        })

                for pe in parsed_entries:
                    rid = pe["rid"]
                    if not rid:
                        continue
                    event = pe["event"]

                    if event.endswith("_started"):
                        continue

                    trace_id = pe["trace_id"]
                    idents = set(pe["idents"])
                    if trace_id and trace_id in traces:
                        idents.update(traces[trace_id])

                    line_str = pe["line"]
                    log_time = pe["time"]
                    jd = pe["json_dict"] or {}

                    if rid.startswith("account_"):
                        sys_id = "account_service"
                        cat = "USER_PROFILE"
                        status_code = str(jd.get("http_status") or "")
                        rows_cnt = str(jd.get("rows") or "")
                        if "404" in status_code or rows_cnt == "0" or "http_status=404" in line_str or "rows=0" in line_str:
                            state = "ABSENT"
                        else:
                            state = "PRESENT"
                    elif rid.startswith("search_"):
                        sys_id = "search_service"
                        cat = "SEARCH_INDEX_ENTRY"
                        res_val = jd.get("result") or ""
                        if res_val == "hit" or "result=hit" in line_str or "total_hits=1" in line_str or "found" in line_str:
                            state = "PRESENT"
                        else:
                            state = "ABSENT"
                    elif rid.startswith("support_"):
                        sys_id = "support_platform"
                        if "attachment" in line_str or "file=" in line_str:
                            cat = "SUPPORT_ATTACHMENT"
                            state = "PRESENT"
                        elif "marker_found=false" in line_str or jd.get("marker_found") is False:
                            cat = "SUPPORT_ATTACHMENT"
                            state = "PRESENT"
                        elif "rows=1" in line_str or jd.get("rows") == "1":
                            cat = "SUPPORT_ATTACHMENT"
                            state = "PRESENT"
                        else:
                            cat = "SUPPORT_MESSAGE"
                            has_pii = bool(jd.get("requester_email") or re.search(r"requester_email=[^n\s]|matched_value=", line_str))
                            state = "PRESENT" if has_pii else "REDACTED"
                    elif rid.startswith("analytics_"):
                        sys_id = "analytics_platform"
                        if "email_opt_in=true" in line_str or jd.get("email_opt_in") is True:
                            cat = "USER_PROFILE"
                            state = "PRESENT"
                        else:
                            cat = "ANALYTICS_PROFILE"
                            has_pii = bool(jd.get("email") or jd.get("user_id") or re.search(r"email=[^n\s]|lookup_key=[^n\s]", line_str))
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                    elif rid.startswith("data_flow_"):
                        sys_id = "integration_service"
                        cat = "DATA_FLOW"
                        en_val = jd.get("enabled")
                        if en_val in (True, "true") or "enabled=true" in line_str:
                            state = "ACTIVE"
                        else:
                            state = "DISABLED"
                    elif rid.startswith("backup_"):
                        sys_id = "backup_service"
                        cat = "BACKUP_ARCHIVE"
                        ra_val = jd.get("restore_allowed")
                        if (
                            ra_val in (True, "true")
                            or "eligible=true deletion_block=false" in line_str
                            or "restore_allowed=true" in line_str
                        ):
                            state = "ACTIVE"
                        else:
                            state = "BLOCKED"
                    elif rid.startswith("audit_record_"):
                        sys_id = "security_service"
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif rid.startswith("tombstone_"):
                        sys_id = "identity_service"
                        cat = "ACCOUNT_TOMBSTONE"
                        state = "PRESENT"
                    else:
                        sys_id = pe["sys_id"] or "unknown"
                        cat = "UNKNOWN"
                        state = "PRESENT"

                    self._add_observation(
                        resource_id=rid,
                        system_id=sys_id,
                        category=cat,
                        state=state,
                        observed_at=log_time,
                        file_id=fid,
                        origin=origin,
                        identifiers=idents,
                        raw_record=pe["json_dict"] or {"log_line": line_str},
                    )
            except Exception:
                pass

    def _load_text_evidence(self):
        txt_path = os.path.join(self.evidence_dir, "records", "customer_account_handover_20261001.txt")
        if not os.path.exists(txt_path):
            return
        meta = self._get_file_metadata(txt_path)
        fid = meta["file_id"]
        origin = meta["origin"]
        cap_at = meta["captured_at"]

        with open(txt_path, mode="r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    t_str, sys_id, rid, cat, status, ident = parts[:6]
                    idents = {ident.lower()} if ident else set()

                    if status in ("NOT_FOUND", "ABSENT"):
                        state = "ABSENT"
                    elif status in ("FOUND", "PRESENT", "IDENTIFIABLE"):
                        state = "PRESENT"
                    elif status == "ACTIVE":
                        state = "ACTIVE"
                    elif status == "ANONYMIZED":
                        state = "ANONYMIZED"
                    elif status == "REDACTED":
                        state = "REDACTED"
                    elif status == "DISABLED":
                        state = "DISABLED"
                    elif status == "BLOCKED":
                        state = "BLOCKED"
                    else:
                        state = "PRESENT"

                    self._add_observation(
                        resource_id=rid,
                        system_id=sys_id,
                        category=cat,
                        state=state,
                        observed_at=t_str or cap_at,
                        file_id=fid,
                        origin=origin,
                        identifiers=idents,
                        raw_record={"handover_line": line},
                    )

    def _load_pdf_evidence(self):
        pdf_pattern = os.path.join(self.evidence_dir, "**", "*.pdf")
        for path in glob.glob(pdf_pattern, recursive=True):
            meta = self._get_file_metadata(path)
            fid = meta["file_id"]
            origin = meta["origin"]
            cap_at = meta["captured_at"]

            try:
                res = subprocess.run(["pdftotext", path, "-"], capture_output=True, text=True)
                text = res.stdout

                emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text))
                uids = set(re.findall(r"\buser_\d+\b", text))
                rids = set(re.findall(r"\b(?:support|audit_record|account|backup|data_flow)_\d+\b", text))

                all_idents = {e.lower() for e in emails} | {u.lower() for u in uids}

                for rid in rids:
                    if rid.startswith("support_"):
                        sys_id = "support_platform"
                        cat = "SUPPORT_ATTACHMENT"
                        state = "PRESENT"
                    elif rid.startswith("audit_record_"):
                        sys_id = "security_service"
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif rid.startswith("account_"):
                        sys_id = "account_service"
                        cat = "USER_PROFILE"
                        state = "PRESENT"
                    else:
                        sys_id = "unknown"
                        cat = "UNKNOWN"
                        state = "PRESENT"

                    self._add_observation(
                        resource_id=rid,
                        system_id=sys_id,
                        category=cat,
                        state=state,
                        observed_at=cap_at,
                        file_id=fid,
                        origin=origin,
                        identifiers=all_idents,
                        raw_record={"pdf_file": os.path.basename(path)},
                    )
            except Exception:
                pass

    def _load_system_activity(self):
        act_path = os.path.join(self.dataset_dir, "system_activity.csv")
        if not os.path.exists(act_path):
            return

        with open(act_path, mode="r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                aid = row["activity_id"].strip()
                t_str = row["event_time"].strip()
                event_type = row["event_type"].strip()
                src = row["source_system"].strip()
                tgt = row["target_system"].strip()
                rid = row["resource_id"].strip()
                result = row["reported_result"].strip()
                details = row["details"].strip()

                emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", details))
                uids = set(re.findall(r"\buser_\d+\b", details))
                idents = {e.lower() for e in emails} | {u.lower() for u in uids}

                state = "PRESENT"
                if event_type == "DELETE_RECORD":
                    state = "ABSENT" if result == "SUCCESS" else "PRESENT"
                elif event_type == "REDACT_RECORD":
                    state = "REDACTED" if result == "SUCCESS" else "PRESENT"
                elif event_type == "ANONYMIZE_RECORD":
                    state = "ANONYMIZED" if result == "SUCCESS" else "PRESENT"
                elif event_type == "BLOCK_RESTORE":
                    state = "BLOCKED" if result == "SUCCESS" else "ACTIVE"
                elif event_type == "DISABLE_DATA_FLOW":
                    state = "DISABLED" if result == "SUCCESS" else "ACTIVE"
                elif event_type == "CHECK_DATA_FLOW":
                    state = "ACTIVE" if "remains enabled" in details else "DISABLED"
                elif event_type == "CHECK_RESTORE_ACCESS":
                    state = "ACTIVE" if "can still be restored" in details else "BLOCKED"
                elif event_type == "RETAIN_RECORD":
                    state = "PRESENT"

                self._add_observation(
                    resource_id=rid,
                    system_id=tgt,
                    category=event_type,
                    state=state,
                    observed_at=t_str,
                    file_id=aid,
                    origin=src,
                    identifiers=idents,
                    raw_record=row,
                )

    def _build_indices(self):
        for obs in self.observations:
            self.observations_by_resource.setdefault(obs.resource_id, []).append(obs)
            for ident in obs.identifiers:
                self.observations_by_ident.setdefault(ident, []).append(obs)

    def find_observations_for_identity(
        self,
        identifiers: Set[str],
        cutoff_time: str,
    ) -> List[ResourceObservation]:
        results = []
        seen_keys = set()

        for ident in identifiers:
            norm_id = self._normalize_ident(ident)
            if not norm_id:
                continue
            for obs in self.observations_by_ident.get(norm_id, []):
                file_cap = self.manifest_by_file_id.get(obs.file_id, {}).get("captured_at")
                if file_cap and file_cap > cutoff_time:
                    continue
                if obs.observed_at <= cutoff_time:
                    k = (obs.resource_id, obs.observed_at, obs.file_id)
                    if k not in seen_keys:
                        seen_keys.add(k)
                        results.append(obs)
        return results

    def get_latest_observation_before_cutoff(
        self,
        resource_id: str,
        cutoff_time: str,
    ) -> Optional[ResourceObservation]:
        obs_list = self.observations_by_resource.get(resource_id, [])
        valid = []
        for o in obs_list:
            file_cap = self.manifest_by_file_id.get(o.file_id, {}).get("captured_at")
            if file_cap and file_cap > cutoff_time:
                continue
            if o.observed_at <= cutoff_time:
                valid.append(o)
        if not valid:
            return None
        valid.sort(key=lambda x: x.observed_at, reverse=True)
        return valid[0]
