import collections
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request

def read_json(url, key):
    request = urllib.request.Request(url, headers={"X-Api-Key": key})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError("NextDNS returned HTTP " + str(error.code)) from None
    except Exception as error:
        raise RuntimeError("NextDNS request failed: " + type(error).__name__) from None

def main():
    ids = [v.strip() for v in os.environ["CLIENT_ID"].split(",") if v.strip()]
    keys = [v.strip() for v in os.environ["AUTH_SECRET"].split(",") if v.strip()]
    if len(ids) != len(keys):
        raise RuntimeError("Profile and key counts differ")
    desired = set()
    for url in os.environ.get("REDIRECT", "").split(","):
        if not url.strip():
            continue
        with urllib.request.urlopen(url.strip(), timeout=20) as response:
            text = response.read().decode("utf-8-sig")
        for line in text.splitlines():
            parts = line.split("#", 1)[0].lower().split()
            if len(parts) != 2:
                continue
            try:
                ipaddress.ip_address(parts[0])
            except ValueError:
                continue
            if parts[0] not in {"0.0.0.0", "127.0.0.1", "::1"}:
                desired.add(parts[1].removeprefix("www."))
    for index, (profile, key) in enumerate(zip(ids, keys), 1):
        base = "https://api.nextdns.io/profiles/" + urllib.parse.quote(profile, safe="") + "/rewrites"
        first = read_json(base, key)
        rows = []
        cursors = set()
        cursor = None
        pages = 0
        while True:
            suffix = ""
            if cursor:
                suffix += "?cursor=" + urllib.parse.quote(cursor, safe="")
            page = read_json(base + suffix, key)
            data = page.get("data", [])
            if not isinstance(data, list):
                raise RuntimeError("Unexpected rewrites response shape")
            rows.extend(data)
            pages += 1
            cursor = (page.get("meta") or {}).get("pagination", {}).get("cursor")
            if not cursor:
                break
            if cursor in cursors or pages >= 20:
                raise RuntimeError("Pagination did not finish")
            cursors.add(cursor)
        names = [r.get("name") for r in rows if r.get("name")]
        pairs = [(r.get("name"), r.get("content")) for r in rows]
        normalized = [n.lower().rstrip(".").removeprefix("*.").removeprefix("www.") for n in names]
        print(json.dumps({
            "profile_number": index, "source_domains": len(desired),
            "default_page_count": len(first.get("data", [])), "all_pages_count": len(rows),
            "pages": pages, "record_fields": sorted({k for r in rows for k in r}),
            "response_fields": sorted(first),
            "default_has_next_cursor": bool((first.get("meta") or {}).get("pagination", {}).get("cursor")),
            "unique_names": len(set(names)), "duplicate_names": len(names) - len(set(names)),
            "duplicate_pairs": len(pairs) - len(set(pairs)),
            "missing_name": len(rows) - len(names),
            "names_in_sources": len(set(names) & desired),
            "normalized_names_in_sources": len(set(normalized) & desired),
            "ids_matching_source_domains": sum(r.get("id") in desired for r in rows),
            "wildcard_names": sum(n.startswith("*.") for n in names)
        }), flush=True)

if __name__ == "__main__":
    main()

