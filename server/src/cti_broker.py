from collections import defaultdict
from datetime import datetime
from hashlib import sha256

import json

class CTIBroker:
    
    # ------------------------------------------------------------------
    # CTI Broker Configuration
    # ------------------------------------------------------------------
    
    _META_FIELDS = {
        "id", "pid",
        "created", "modified",
        "valid_from", "valid_until",
        "revoked", "spec_version",
        "tlp", "risk",
        "origin", "history",
        "mtime","ctime","atime"
    }

    _TLP_LEVELS = {"white": 0, "green": 1, "amber": 2, "red": 3}

    def __init__(self, cti_db):
        self.cti_db = cti_db
        self.fingerprints = {}
        self.ids_to_fps = {}

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------ 

    def create(self,obj,origin=None,tlp=None,risk=None):
        fp = self._fingerprint(obj)
        if fp in self.fingerprints:
            return False
        if tlp is None:
            tlp = "white"
        if risk is None:
            risk = 0
        if origin is None:
            origin = "unknown"
        timestamp = datetime.now().isoformat()
        self.fingerprints[fp] = {
            'id': obj['id'],
            'type': obj['type'],
            'tlp': tlp,
            'risk': risk,
            'origin': origin,
            'history': [f'''{timestamp}: Created by {origin} [{tlp}, {risk}]'''],
        }
        self.ids_to_fps[obj['id']] = fp
        return True

    def read(self, fp=None,id=None):
        if fp is None and id is None:
            return {}
        if id is not None:
            fp = self.ids_to_fps.get(id)
        return self.fingerprints[fp] if fp in self.fingerprints else {}
    
    def update(self, obj, origin=None, tlp=None, risk=None):
        existing_fp = self.ids_to_fps.get(obj['id'])
        fp = self._fingerprint(obj)
        timestamp = datetime.now().isoformat()
        updated_obj = False
        if fp != existing_fp:
            fp_content = self.fingerprints[existing_fp]
            self.fingerprints.pop(existing_fp, None)
            self.fingerprints[fp] = fp_content
            self.ids_to_fps[obj['id']] = fp
            updated_obj = True
        if updated_obj:
            self.fingerprints[fp]['history'].append(f'''{timestamp}: Object updated by {origin}''')
        updated_tlp = self.set_tlp(fp, tlp)
        if updated_tlp:
            self.fingerprints[fp]['history'].append(f'''{timestamp}: TLP updated by {origin} to {tlp}''')
        updated_risk = self.set_risk(fp, risk)
        if updated_risk:
            self.fingerprints[fp]['history'].append(f'''{timestamp}: Risk updated by {origin} to {risk}''')
        return updated_obj or updated_tlp or updated_risk

    def delete(self, obj_id):
        fp = self.ids_to_fps.pop(obj_id, None)
        if fp:
            self.fingerprints.pop(fp, None)
            return True
        return False

    # ------------------------------------------------------------------
    # Setters
    # ------------------------------------------------------------------
    
    def set_tlp(self, fp, tlp):
        if fp not in self.fingerprints or tlp is None:
            return False
        if tlp not in CTIBroker._TLP_LEVELS:
            return False
        if CTIBroker._TLP_LEVELS[tlp] <= CTIBroker._TLP_LEVELS[self.fingerprints[fp]['tlp']]:
            return False
        self.fingerprints[fp]['tlp'] = tlp

    def set_risk(self, fp, risk):
        if fp not in self.fingerprints or risk is None:
            return False
        if risk <= self.fingerprints[fp]['risk']:
            return False
        self.fingerprints[fp]['risk'] = risk
        return True

    def set_history(self, obj_id, message):
        fp = self.ids_to_fps[obj_id]
        if fp:
            self.fingerprints[fp]['history'].append(message)
            return True
        return False

    # ------------------------------------------------------------------
    # Query Functions
    # ------------------------------------------------------------------

    def check_if_exists(self, obj):
        fp = self._fingerprint(obj)
        if fp in self.fingerprints:
            return True, self.fingerprints[fp]['id']
        return False, None

    # ------------------------------------------------------------------
    # Advanced Functions
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(stix_obj):
        if not isinstance(stix_obj, dict):
            stix_obj = json.loads(stix_obj.serialize())
        obj_copy = {k: v for k, v in stix_obj.items()
                    if k not in CTIBroker._META_FIELDS}
        canonical = json.dumps(obj_copy, sort_keys=True, separators=(",", ":"))
        return sha256(canonical.encode("utf-8")).hexdigest()

    def decay(self, decay_factor):
        for fp, data in self.fingerprints.items():
            if data['risk'] > 0:
                data['risk'] = data['risk'] - decay_factor
                if data['risk'] % 10 == 0:
                    data['history'].append(f'''{datetime.now().isoformat()}: Risk decayed to {data['risk']}''')

    def access_risks(self):
        type_risks = defaultdict(list)
        for data in self.fingerprints.values():
            if data['risk'] > 0:
                type_risks[data['type']].append(data['risk'])
        return {t: sum(risks) / len(risks) for t, risks in type_risks.items()}