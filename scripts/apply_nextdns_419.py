import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import random
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

CONFIG = pathlib.Path(__file__).with_name("nextdns-419-public.json")
CERT = pathlib.Path(__file__).with_name("nextdns-audit-public.pem")

def fingerprint(rows):
    values = sorted([r["name"], r["content"], r.get("type", "A")] for r in rows)
    return hashlib.sha256(json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def encrypt(name, value):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as file:
        json.dump(value, file)
        temporary = file.name
    try:
        result = subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes256",
                                 "-in", temporary, "-out", name, "-outform", "DER", str(CERT)],
                                capture_output=True)
        if result.returncode:
            raise RuntimeError("Audit encryption failed")
    finally:
        pathlib.Path(temporary).unlink()

def plan(before, config):
    if fingerprint(before) != config["expected_before_sha256"]:
        raise RuntimeError("Profile changed since the approved snapshot; refusing migration")
    with urllib.request.urlopen(config["historical_source"], timeout=20) as response:
        text = response.read().decode("utf-8-sig")
    historical = set()
    for line in text.splitlines():
        values = line.split("#", 1)[0].lower().split()
        if len(values) != 2:
            continue
        try:
            ipaddress.ip_address(values[0])
        except ValueError:
            continue
        historical.add((values[1].removeprefix("www."), values[0]))
    legacy = [r for r in before if (r["name"], r["content"]) in historical]
    preserved = [r for r in before if (r["name"], r["content"]) not in historical]
    target = [{"name": r["name"], "content": r["content"]} for r in preserved] + config["public_rules"]
    if (len(before), len(legacy), len(preserved), len(config["public_rules"]), len(target)) != (500, 489, 11, 408, 419):
        raise RuntimeError("Migration counts differ from the approved 500 -> 419 plan")
    if len({r["name"] for r in target}) != len(target):
        raise RuntimeError("Duplicate names in proposed plan")
    for row in target:
        if ipaddress.ip_address(row["content"]).version != 4:
            raise RuntimeError("Unexpected address type in approved plan")
    return legacy, preserved, target

class Api:
    def __init__(self, profile, key):
        self.base = "https://api.nextdns.io/profiles/" + urllib.parse.quote(profile, safe="")
        self.key = key

    def request(self, method, suffix, value=None):
        body = None if value is None else json.dumps(value).encode()
        for attempt in range(5):
            request = urllib.request.Request(self.base + suffix, data=body, method=method,
                    headers={"X-Api-Key": self.key, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=25) as response:
                    raw = response.read()
                    result = json.loads(raw) if raw else {}
                if isinstance(result, dict) and result.get("errors"):
                    raise RuntimeError("NextDNS returned errors in a successful response")
                return result
            except urllib.error.HTTPError as error:
                if error.code in (429, 524) and attempt < 4:
                    print("API rate limit; waiting 60 seconds", flush=True)
                    time.sleep(60)
                    continue
                try:
                    codes = [e.get("code", "unknown") for e in json.load(error).get("errors", [])]
                except Exception:
                    codes = []
                raise RuntimeError("NextDNS HTTP " + str(error.code) + " " + ",".join(codes)) from None
            except (urllib.error.URLError, TimeoutError) as error:
                raise RuntimeError("NextDNS connection failed: " + type(error).__name__) from None
        raise RuntimeError("API retry budget exhausted")

    def rows(self):
        result = self.request("GET", "/rewrites")
        if (result.get("meta") or {}).get("pagination", {}).get("cursor"):
            raise RuntimeError("Unexpected pagination; refusing incomplete rewrite snapshot")
        return result["data"]

def reconcile(api, target):
    current = api.rows()
    wanted = {(r["name"], r["content"]) for r in target}
    for index, row in enumerate(current, 1):
        if (row["name"], row["content"]) not in wanted:
            api.request("DELETE", "/rewrites/" + urllib.parse.quote(row["id"], safe=""))
        if index % 50 == 0:
            print("Reviewed existing rewrites:", index, flush=True)
    existing = {(r["name"], r["content"]) for r in api.rows()}
    for index, row in enumerate(target, 1):
        if (row["name"], row["content"]) not in existing:
            api.request("POST", "/rewrites", {"name": row["name"], "content": row["content"]})
        if index % 50 == 0:
            print("Reviewed target rewrites:", index, flush=True)

def analytics(api):
    result = {"domains": [], "truncated": False}
    suffix = "/analytics/domains?from=-30d&limit=500"
    try:
        for _ in range(10):
            page = api.request("GET", suffix)
            result["domains"].extend(page.get("data", []))
            cursor = (page.get("meta") or {}).get("pagination", {}).get("cursor")
            if not cursor:
                break
            suffix = "/analytics/domains?from=-30d&limit=500&cursor=" + urllib.parse.quote(cursor, safe="")
        else:
            result["truncated"] = True
        result["status"] = api.request("GET", "/analytics/status?from=-30d")
        result["reasons"] = api.request("GET", "/analytics/reasons?from=-30d&limit=100")
    except RuntimeError as error:
        result["error"] = str(error)
    return result

def skip_name(data, position):
    while data[position]:
        length = data[position]
        if length & 192 == 192:
            return position + 2
        position += length + 1
    return position + 1

def dns_probe(profile, domain):
    query = struct.pack("!6H", random.randrange(65536), 256, 1, 0, 0, 0)
    query += b"".join(bytes([len(label)]) + label.encode() for label in domain.split("."))
    query += bytes([0]) + struct.pack("!2H", 1, 1)
    endpoint = "https://dns.nextdns.io/" + urllib.parse.quote(profile, safe="")
    try:
        request = urllib.request.Request(endpoint, data=query,
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        with urllib.request.urlopen(request, timeout=10) as response:
            data = response.read()
        _, flags, questions, answers, _, _ = struct.unpack_from("!6H", data)
        position = 12
        for _ in range(questions):
            position = skip_name(data, position) + 4
        ips = []
        for _ in range(answers):
            position = skip_name(data, position)
            kind, _, _, size = struct.unpack_from("!HHIH", data, position)
            position += 10
            if kind == 1 and size == 4:
                ips.append(".".join(str(value) for value in data[position:position+size]))
            position += size
        return {"domain": domain, "rcode": flags & 15, "ips": ips}
    except Exception as error:
        return {"domain": domain, "error_type": type(error).__name__}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--preview-snapshot")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text(encoding="utf-8-sig"))
    if args.preview_snapshot:
        before = json.loads(pathlib.Path(args.preview_snapshot).read_text())["rewrites"]
        legacy, preserved, target = plan(before, config)
        print(json.dumps({"before": len(before), "legacy": len(legacy), "preserve": len(preserved),
                          "new": len(config["public_rules"]), "target": len(target),
                          "expected_before_sha256": fingerprint(before)}))
        return
    ids = [x.strip() for x in os.environ["CLIENT_ID"].split(",") if x.strip()]
    keys = [x.strip() for x in os.environ["AUTH_SECRET"].split(",") if x.strip()]
    if len(ids) != 1 or len(keys) != 1:
        raise RuntimeError("This approved migration applies to exactly one profile")
    api = Api(ids[0], keys[0])
    before = api.rows()
    legacy, preserved, target = plan(before, config)
    encrypt("nextdns-before.cms", {"rewrites": before})
    audit = {"before_analytics": analytics(api)}
    encrypt("nextdns-analytics.cms", audit)
    print("Approved plan validated: 500 -> 419, preserving 11 unknown records", flush=True)
    try:
        try:
            api.request("PUT", "/rewrites", target)
            print("Applied rewrite array in one request", flush=True)
        except RuntimeError as error:
            current = api.rows()
            if fingerprint(current) != fingerprint(before):
                raise
            if not (str(error).startswith("NextDNS HTTP 400") or str(error).startswith("NextDNS HTTP 405") or str(error).startswith("NextDNS HTTP 404")):
                raise
            print("Array replacement unavailable; applying reviewed per-record changes", flush=True)
            reconcile(api, target)
        after = api.rows()
        if fingerprint(after) != fingerprint(target):
            raise RuntimeError("Post-update rewrite verification failed")
    except Exception:
        print("Migration failed; restoring original rewrite answers", flush=True)
        reconcile(api, before)
        if fingerprint(api.rows()) != fingerprint(before):
            raise RuntimeError("Rollback verification failed; encrypted backup is available") from None
        print("Original 500-rule snapshot restored", flush=True)
        raise
    answers = {r["name"]: r["content"] for r in target}
    probes = []
    for domain in ("chatgpt.com", "api.openai.com", "claude.ai", "deepl.com", "gemini.google.com",
                   "nextdns-inheritance-check.chatgpt.com"):
        probe = dns_probe(ids[0], domain)
        parent = domain
        while parent not in answers and "." in parent:
            parent = parent.split(".", 1)[1]
        probe["expected"] = answers.get(parent)
        probe["matches"] = probe["expected"] in probe.get("ips", [])
        probes.append(probe)
    audit["dns_probes"] = probes
    audit["after"] = after
    encrypt("nextdns-after.cms", audit)
    print("MIGRATION_VERIFIED 419 rules; 11 unknown records preserved", flush=True)
    print("DNS_PROBES_MATCHED", sum(p["matches"] for p in probes), "of", len(probes), flush=True)

if __name__ == "__main__":
    main()
