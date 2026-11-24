import json, pathlib, collections
c = collections.Counter()
for f in pathlib.Path("cache/rdap").glob("*.json"):
    d = json.loads(f.read_text("utf-8"))
    c["ok" if "events" in d else
      f"http {d.get('_notfound')}" if "_notfound" in d else
      d.get("_error", "?")] += 1
print(c.most_common())