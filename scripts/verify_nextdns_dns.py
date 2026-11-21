import concurrent.futures
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

EXPECTED = "8ce5574b09814e46359d818300514bf553706a6dd6193311d6a7ff8887a83de9"

def api(profile, key, suffix):
    req = urllib.request.Request("https://api.nextdns.io/profiles/" + urllib.parse.quote(profile, safe="") + suffix,
                                 headers={"X-Api-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError("API HTTP " + str(error.code)) from None

def digest(rows):
    values = sorted([r["name"], r["content"], r.get("type", "A")] for r in rows)
    return hashlib.sha256(json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def name_at(data, position):
    labels = []
    end = None
    seen = set()
    while data[position]:
        size = data[position]
        if size & 192 == 192:
            if end is None:
                end = position + 2
            position = ((size & 63) << 8) | data[position+1]
            if position in seen:
                raise ValueError("DNS compression cycle")
            seen.add(position)
            continue
        labels.append(data[position+1:position+1+size].decode("ascii"))
        position += size + 1
    return ".".join(labels) or ".", end if end is not None else position + 1

def probe(profile, domain, qtype):
    query = struct.pack("!6H", random.randrange(65536), 256, 1, 0, 0, 0)
    query += b"".join(bytes([len(label)]) + label.encode() for label in domain.split("."))
    query += bytes([0]) + struct.pack("!2H", qtype, 1)
    try:
        req = urllib.request.Request("https://dns.nextdns.io/" + urllib.parse.quote(profile, safe=""), data=query,
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        with urllib.request.urlopen(req, timeout=12) as response:
            data = response.read()
        _, flags, questions, answers, _, _ = struct.unpack_from("!6H", data)
        position = 12
        for _ in range(questions):
            _, position = name_at(data, position)
            position += 4
        records = []
        for _ in range(answers):
            _, position = name_at(data, position)
            kind, _, _, size = struct.unpack_from("!HHIH", data, position)
            position += 10
            row = {"type": kind}
            if kind in (1, 28):
                row["ip"] = str(ipaddress.ip_address(data[position:position+size]))
            elif kind in (5, 65):
                if kind == 5:
                    row["target"], _ = name_at(data, position)
                else:
                    row["priority"] = struct.unpack_from("!H", data, position)[0]
                    row["target"], param = name_at(data, position+2)
                    row["hints"] = []
                    while param < position + size:
                        key, length = struct.unpack_from("!HH", data, param)
                        param += 4
                        if key in (4, 6):
                            width = 4 if key == 4 else 16
                            row["hints"].extend(str(ipaddress.ip_address(data[p:p+width]))
                                                for p in range(param, param+length, width))
                        param += length
            records.append(row)
            position += size
        return {"domain": domain, "qtype": qtype, "rcode": flags & 15, "answers": records}
    except Exception as error:
        return {"domain": domain, "qtype": qtype, "error_type": type(error).__name__}

def encrypt(value):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as file:
        json.dump(value, file)
        path = file.name
    try:
        result = subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes256",
                "-in", path, "-out", "nextdns-audit-verification.cms", "-outform", "DER",
                "scripts/nextdns-audit-public.pem"], capture_output=True)
        if result.returncode:
            raise RuntimeError("Verification encryption failed")
    finally:
        pathlib.Path(path).unlink()

def main():
    ids = [v.strip() for v in os.environ["CLIENT_ID"].split(",") if v.strip()]
    keys = [v.strip() for v in os.environ["AUTH_SECRET"].split(",") if v.strip()]
    if len(ids) != 1 or len(keys) != 1:
        raise RuntimeError("Expected one profile")
    profile, key = ids[0], keys[0]
    rows = None
    for attempt in range(24):
        try:
            rows = api(profile, key, "/rewrites")["data"]
        except RuntimeError:
            time.sleep(30)
            continue
        if digest(rows) == EXPECTED:
            break
        print("Waiting for approved profile state; current rule count:", len(rows), flush=True)
        time.sleep(30)
    else:
        raise RuntimeError("Approved profile state was not observed")
    print("Approved 419-rule state observed", flush=True)
    domains = ["chatgpt.com", "api.openai.com", "claude.ai", "deepl.com", "gemini.google.com",
               "nextdns-inheritance-check.chatgpt.com"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(probe, profile, domain, qtype) for domain in domains for qtype in (1, 28, 65)]
        probes = [f.result() for f in futures]
    answers = {r["name"]: r["content"] for r in rows}
    for record in probes:
        parent = record["domain"]
        while parent not in answers and "." in parent:
            parent = parent.split(".", 1)[1]
        record["expected_ipv4"] = answers.get(parent)
    report = {"rewrites": rows, "dns": probes}
    for label, suffix in (("logging_settings", "/settings/logs"), ("devices", "/analytics/devices?from=-30d&limit=100")):
        try:
            report[label] = api(profile, key, suffix)
        except RuntimeError as error:
            report[label] = {"error": str(error)}
    encrypt(report)
    print("DNS A/AAAA/HTTPS verification encrypted; private metadata omitted from logs", flush=True)

if __name__ == "__main__":
    main()
