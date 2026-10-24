"""Identity resolution module connecting current snapshots with historical audit trails and hashes."""

import csv
import hashlib
from typing import Dict, Optional, Set
from code.models import IdentityProfile


class IdentityResolver:
    def __init__(self, identities_csv: str, audit_log_csv: str):
        self.profiles_by_user_id: Dict[str, IdentityProfile] = {}
        self.lookup_index: Dict[str, str] = {}  # identifier/hash -> user_id
        self._load_identities(identities_csv)
        self._load_audit_log(audit_log_csv)
        self._compute_all_hashes()

    def _normalize(self, val: Optional[str]) -> Optional[str]:
        if not val or val == "null" or val == "None":
            return None
        return val.strip().lower()

    def _sha256(self, val: str) -> str:
        return hashlib.sha256(val.strip().lower().encode("utf-8")).hexdigest()

    def _load_identities(self, csv_path: str):
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row["name"].strip() if row.get("name") else None
                email = row["email"].strip().lower() if row.get("email") else None
                phone = row["phone"].strip() if row.get("phone") else None
                email_hash = row["email_hash"].strip().lower() if row.get("email_hash") else None

                profile = IdentityProfile(
                    user_id=uid,
                    primary_email=email or "",
                    name=name,
                    phone=phone,
                    email_hash=email_hash,
                )
                if uid:
                    profile.emails.add(uid.lower())
                    self.lookup_index[uid.lower()] = uid
                if email:
                    profile.emails.add(email)
                    self.lookup_index[email] = uid
                    h = self._sha256(email)
                    profile.email_hashes.add(h)
                    self.lookup_index[h] = uid
                if phone:
                    profile.phones.add(phone.lower())
                    self.lookup_index[phone.lower()] = uid
                if name:
                    profile.names.add(name.lower())
                if email_hash:
                    profile.email_hashes.add(email_hash)
                    self.lookup_index[email_hash] = uid

                self.profiles_by_user_id[uid] = profile

    def _load_audit_log(self, csv_path: str):
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                field = row["field_name"].strip().lower()
                old_val = row["old_value"].strip() if row.get("old_value") else None
                new_val = row["new_value"].strip() if row.get("new_value") else None

                if uid not in self.profiles_by_user_id:
                    self.profiles_by_user_id[uid] = IdentityProfile(
                        user_id=uid,
                        primary_email="",
                    )
                profile = self.profiles_by_user_id[uid]

                if field == "email":
                    if old_val:
                        norm_old = old_val.lower()
                        profile.emails.add(norm_old)
                        self.lookup_index[norm_old] = uid
                        h_old = self._sha256(norm_old)
                        profile.email_hashes.add(h_old)
                        self.lookup_index[h_old] = uid
                    if new_val:
                        norm_new = new_val.lower()
                        profile.emails.add(norm_new)
                        self.lookup_index[norm_new] = uid
                        h_new = self._sha256(norm_new)
                        profile.email_hashes.add(h_new)
                        self.lookup_index[h_new] = uid
                elif field == "phone":
                    if old_val:
                        profile.phones.add(old_val.lower())
                        self.lookup_index[old_val.lower()] = uid
                    if new_val:
                        profile.phones.add(new_val.lower())
                        self.lookup_index[new_val.lower()] = uid
                elif field == "name":
                    if old_val:
                        profile.names.add(old_val.lower())
                    if new_val:
                        profile.names.add(new_val.lower())

    def _compute_all_hashes(self):
        for uid, profile in self.profiles_by_user_id.items():
            for em in list(profile.emails):
                if "@" in em:
                    h = self._sha256(em)
                    profile.email_hashes.add(h)
                    self.lookup_index[h] = uid

    def resolve(self, identifier: str) -> Optional[IdentityProfile]:
        norm = identifier.strip().lower()
        uid = self.lookup_index.get(norm)
        if uid and uid in self.profiles_by_user_id:
            return self.profiles_by_user_id[uid]
        return None

    def get_all_identifiers(self, profile: IdentityProfile) -> Set[str]:
        all_idents = set()
        all_idents.add(profile.user_id.lower())
        all_idents.update(profile.emails)
        all_idents.update(profile.phones)
        all_idents.update(profile.email_hashes)
        return all_idents
