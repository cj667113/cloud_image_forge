"""Bounded, read-only systemd evidence from a mounted guest filesystem.

This is an offline configuration graph, not a systemd transaction simulator.
No guest programs or host service-manager commands are executed. In particular,
ordering edges have no measured durations and do not imply activation edges.
"""
from __future__ import annotations

from collections import defaultdict, deque
import posixpath
import re


LOAD_PATHS = ("/etc/systemd/system.control", "/etc/systemd/system",
              "/etc/systemd/system.attached", "/usr/local/lib/systemd/system",
              "/usr/lib/systemd/system", "/lib/systemd/system")
RELATIONS = {"Requires", "Wants", "Requisite", "BindsTo", "PartOf", "Upholds",
             "Conflicts", "After", "Before", "OnFailure"}
ACTIVATION = {"Requires", "Wants", "Requisite", "BindsTo", "Upholds"}
UNIT_NAME = re.compile(r"[A-Za-z0-9_:.@\\-]+\.(?:service|socket|device|mount|automount|swap|target|path|timer|slice|scope)\Z")
LIMITS = {"units": 1200, "edges": 10000, "file_bytes": 256 * 1024,
          "total_bytes": 8 * 1024 * 1024, "directory_entries": 16000}
SCOPE = [
    "Offline configuration only: startup times and an actual critical path require a running guest.",
    "Requires/Wants and startup ordering are separate. After/Before applies only when both units start.",
    "Runtime/generated units, implicit/default dependencies, socket activation and mount-derived dependencies are not synthesized. Conditions are not evaluated.",
    "Enablement is inferred from installed dependency links; it does not prove a unit ran or is reachable from the default target.",
]


def _valid(name):
    return isinstance(name, str) and len(name) <= 255 and bool(UNIT_NAME.fullmatch(name)) and name.count("@") <= 1


def _template(name):
    if "@" not in name:
        return None
    prefix, instance = name.rsplit(".", 1)[0].split("@", 1)
    return f"{prefix}@.{name.rsplit('.', 1)[1]}" if instance else None


def _compatible_alias(source, target):
    source_stem, source_type = source.rsplit(".", 1)
    target_stem, target_type = target.rsplit(".", 1)
    source_instance = source_stem.split("@", 1)[1] if "@" in source_stem else None
    target_instance = target_stem.split("@", 1)[1] if "@" in target_stem else None
    return source_type == target_type and source_instance == target_instance


def _dropin_names(name):
    """Least to most specific, before load-path priority is considered."""
    stem, kind = name.rsplit(".", 1)
    names = [kind + ".d"]
    names.extend(stem[:match.end()] + "." + kind + ".d" for match in re.finditer("-", stem))
    template = _template(name)
    if template:
        names.append(template + ".d")
    names.append(name + ".d")
    return list(dict.fromkeys(names))


def _statements(text):
    """Parse only evidence fields; retain duplicate keys and continuation lines."""
    section, pending = "", ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        trailing = len(line) - len(line.rstrip("\\"))
        if trailing % 2:
            pending += line[:-1] + " "
            continue
        line, pending = (pending + line).strip(), ""
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif "=" in line:
            key, value = line.split("=", 1)
            yield section, key.strip(), value.strip()
    if pending:
        yield "__error__", "Continuation", "Unterminated continuation line"


def _words(value):
    # Keep escaped unit-name bytes (e.g. dev-disk-by\\x2duuid...) intact.
    words = re.findall(r'''"[^"\n]*"|'[^'\n]*'|[^\s]+''', value)
    return [word[1:-1] if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'" else word
            for word in words]


def _expand(value, name):
    stem = name.rsplit(".", 1)[0]
    instance = stem.split("@", 1)[1] if "@" in stem else ""
    values = {"%": "%", "n": name, "N": stem, "p": stem.split("@", 1)[0], "i": instance}
    if re.search(r"%(?![%nNpi])", value) or ("%i" in value and not instance):
        return None
    return re.sub(r"%(.)", lambda match: values[match[1]], value)


class _Inspector:
    def __init__(self, guest):
        self.g = guest
        self.warnings = list(SCOPE)
        self.truncated = False
        self.entries = self.bytes = 0
        self.dirs, self.texts, self.fragments, self.resolved = {}, {}, {}, {}
        self.aliases, self.units, self.edges = {}, {}, {}
        self.children = {}

    def warn(self, message, *, truncated=False):
        self.truncated |= truncated
        if message not in self.warnings and len(self.warnings) < 100:
            self.warnings.append(message[:500])

    def listing(self, path):
        if path in self.dirs:
            return self.dirs[path]
        result = []
        try:
            if self.g.is_dir(path):
                names = self.g.ls(path)
                remaining = max(0, LIMITS["directory_entries"] - self.entries)
                if len(names) > remaining:
                    self.warn("Directory-entry limit reached; some units or drop-ins were omitted.", truncated=True)
                result = sorted(name for name in names[:remaining] if isinstance(name, str) and
                                name not in {".", ".."} and "/" not in name and "\x00" not in name)
                self.entries += len(result)
        except RuntimeError:
            self.warn(f"Could not list {path}; evidence from this directory is incomplete.")
        self.dirs[path] = result
        return result

    def follow(self, path):
        """Resolve leaf links inside the appliance, with a fixed hop budget."""
        seen = set()
        for _ in range(24):
            path = posixpath.normpath(path)
            if path == "/dev/null":
                return path, "masked"
            if path in seen or len(path) > 4096 or not path.startswith("/") or "\x00" in path:
                return path, "unreadable"
            seen.add(path)
            try:
                if not self.g.is_symlink(path):
                    return path, "loaded" if self.g.is_file(path) else "missing"
                link = self.g.readlink(path)
                path = link if link.startswith("/") else posixpath.join(posixpath.dirname(path), link)
            except RuntimeError:
                return path, "unreadable"
        return path, "unreadable"

    def resolve(self, name, seen=()):
        if name in self.resolved:
            return self.resolved[name]
        if name in seen or len(seen) >= 24:
            return name, None, "unreadable"
        path = self.fragments.get(name)
        if not path and _template(name):
            path = self.fragments.get(_template(name))
        if not path:
            return name, None, "missing"
        target, state = self.follow(path)
        target_name = posixpath.basename(target)
        # Links outside the load path are linked fragments, not aliases. Guestfs
        # still confines their bounded reads to the guest filesystem.
        if state == "loaded" and posixpath.dirname(target) in LOAD_PATHS and _valid(target_name):
            if _template(name) and target_name.endswith("@." + name.rsplit(".", 1)[1]):
                target_name = target_name.replace("@.", "@" + name.rsplit(".", 1)[0].split("@", 1)[1] + ".", 1)
            if target_name != name:
                if not _compatible_alias(name, target_name):
                    result = name, target, "unreadable"
                else:
                    result = self.resolve(target_name, (*seen, name))
                    if result[0] != name and result[2] != "unreadable":
                        self.aliases[name] = result[0]
                self.resolved[name] = result
                return result
        result = name, target, state
        self.resolved[name] = result
        return result

    def read(self, path):
        if path in self.texts:
            return self.texts[path]
        try:
            size = self.g.filesize(path)
            if size > LIMITS["file_bytes"] or self.bytes + size > LIMITS["total_bytes"]:
                self.warn("Unit-file read limit reached; oversized or excess files were omitted.", truncated=True)
                result = None
            else:
                data = self.g.read_file(path)
                self.bytes += size
                result = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
                if "\x00" in result:
                    result = None
        except RuntimeError:
            result = None
        self.texts[path] = result
        return result

    def dropins(self, name, aliases):
        selected = {}
        for alias in [*sorted(aliases), name]:
            for specificity, directory in enumerate(_dropin_names(alias)):
                for priority, root in enumerate(reversed(LOAD_PATHS)):
                    if directory not in self.children.get(root, ()):
                        continue
                    for filename in self.listing(root + "/" + directory):
                        if filename.startswith(".") or not filename.endswith(".conf"):
                            continue
                        candidate = (specificity, priority, root + "/" + directory + "/" + filename)
                        if filename not in selected or candidate[:2] >= selected[filename][:2]:
                            selected[filename] = candidate
        if len(selected) > 64:
            self.warn(f"Drop-in limit reached for {name}.", truncated=True)
        return [selected[key][2] for key in sorted(selected)[:64]]

    def edge(self, source, target, relation, origin, path):
        if not _valid(target):
            return
        canonical = self.resolve(target)[0]
        key = source, canonical, relation
        if len(self.edges) >= LIMITS["edges"] and key not in self.edges:
            self.warn("Dependency-edge limit reached; the graph is incomplete.", truncated=True)
            return
        self.edges.setdefault(key, {"source": source, "target": canonical, "relation": relation,
                                    "origin": origin, "path": path})

    def unit(self, name):
        name, fragment, state = self.resolve(name)
        if name in self.units:
            return self.units[name]
        aliases = sorted(alias for alias, target in self.aliases.items() if target == name)
        unit = {"name": name, "description": "", "type": name.rsplit(".", 1)[1],
                "load_state": state, "unit_file_state": "unknown", "fragment_path": fragment,
                "dropins": [], "aliases": aliases, "enabled_by": [], "service_type": None,
                "default_dependencies": True, "conditions": [], "warnings": [],
                "is_template": name.rsplit(".", 1)[0].endswith("@")}
        self.units[name] = unit
        if state != "loaded":
            if state == "masked":
                unit["unit_file_state"] = "masked"
            else:
                unit["warnings"].append("The unit fragment is missing or could not be read; runtime generators may supply it.")
            return unit
        text = self.read(fragment)
        if text is None:
            unit["load_state"] = "unreadable"
            unit["warnings"].append("The unit fragment could not be read within inspection limits.")
            return unit
        if text == "":
            unit.update(load_state="masked", unit_file_state="masked")
            return unit
        configs = [(fragment, text, "unit")]
        for path in self.dropins(name, aliases):
            resolved, state = self.follow(path)
            unit["dropins"].append(path)
            if state == "masked":
                continue
            content = self.read(resolved) if state == "loaded" else None
            if content is None:
                unit["warnings"].append(f"Unreadable drop-in: {path}")
            else:
                configs.append((path, content, "dropin"))
        install_settings, conditions, assertions = {}, [], []
        for path, content, origin in configs:
            for index, (section, key, value) in enumerate(_statements(content)):
                if index >= 4096:
                    self.warn(f"Directive limit reached for {path}.", truncated=True)
                    break
                if section == "Unit" and key in RELATIONS:
                    # systemd dependencies are additive, including an empty
                    # assignment in a drop-in: it cannot remove old edges.
                    targets = _words(value)
                    if len(targets) > LIMITS["units"]:
                        self.warn(f"Reference limit reached for {name}.", truncated=True)
                    for target in targets[:LIMITS["units"]]:
                        expanded = _expand(target, name)
                        if expanded is None or not _valid(expanded):
                            message = f"Unresolved {key} reference: {target[:150]}"
                            if message not in unit["warnings"] and len(unit["warnings"]) < 12:
                                unit["warnings"].append(message)
                        else:
                            self.edge(name, expanded, key, origin, path)
                elif section == "Unit" and key == "Description":
                    unit["description"] = (_expand(value, name) or value)[:500]
                elif section == "Unit" and key == "DefaultDependencies":
                    if value.lower() in {"no", "false", "0", "off"}:
                        unit["default_dependencies"] = False
                    elif value.lower() in {"yes", "true", "1", "on"}:
                        unit["default_dependencies"] = True
                elif section == "Unit" and key.startswith(("Condition", "Assert")):
                    bucket = conditions if key.startswith("Condition") else assertions
                    if not value:
                        bucket.clear()
                    elif len(bucket) < 32:
                        bucket.append(f"{key}={value[:400]}")
                elif section == "Unit" and key in {"RequiresMountsFor", "WantsMountsFor"} and value:
                    unit["warnings"].append(f"{key} mount-derived dependencies require runtime resolution.")
                elif section == "Service" and key == "Type":
                    unit["service_type"] = value[:80] or None
                elif section == "Install" and key in {"WantedBy", "RequiredBy", "UpheldBy", "Alias", "Also"}:
                    if value:
                        install_settings[key] = True
                    else:
                        install_settings.pop(key, None)
                elif section == "__error__":
                    unit["warnings"].append(value)
        unit["conditions"] = conditions + assertions
        unit["warnings"] = list(dict.fromkeys(unit["warnings"]))[:12]
        unit["unit_file_state"] = "disabled" if install_settings else "static"
        return unit

    def inspect(self):
        for root in LOAD_PATHS:
            self.children[root] = self.listing(root)
            for name in self.children[root]:
                if _valid(name) and name not in self.fragments:
                    if len(self.fragments) >= LIMITS["units"]:
                        self.warn("Installed-unit limit reached; some fragments were omitted.", truncated=True)
                    else:
                        self.fragments[name] = root + "/" + name
        # Dependency directories add real pull-in edges, unlike [Install]
        # WantedBy= declarations, which are only enablement instructions.
        links = {}
        for root in LOAD_PATHS:
            for directory in self.children[root]:
                relation = "Wants" if directory.endswith(".wants") else "Requires" if directory.endswith(".requires") else None
                if not relation:
                    continue
                owner = directory.rsplit(".", 1)[0]
                if not _valid(owner):
                    continue
                for name in self.listing(root + "/" + directory):
                    if not _valid(name) or (owner, name, relation) in links:
                        continue
                    path = root + "/" + directory + "/" + name
                    try:
                        if not self.g.is_symlink(path):
                            continue
                    except RuntimeError:
                        self.warn(f"Could not inspect dependency link {path}.")
                        continue
                    links[(owner, name, relation)] = path
                    if name not in self.fragments and len(self.fragments) < LIMITS["units"]:
                        self.fragments[name] = path
        # Resolve aliases before parsing so alias drop-ins are included even
        # when the canonical fragment sorts before its alias.
        for name in sorted(self.fragments):
            self.resolve(name)
        seeds = list(dict.fromkeys(self.resolve(name)[0] for name in sorted(self.fragments)))
        for (source, target, relation), path in links.items():
            source = self.resolve(source)[0]
            self.edge(source, target, relation, "enablement", path)
            seeds.append(source)
        queue, queued = deque(seeds), set(seeds)
        while queue and len(self.units) < LIMITS["units"]:
            name = queue.popleft()
            if name in self.units:
                continue
            unit = self.unit(name)
            for edge in self.edges.values():
                if edge["source"] == unit["name"] and edge["target"] not in queued:
                    queue.append(edge["target"])
                    queued.add(edge["target"])
        if queue:
            self.warn("Referenced-unit limit reached; the graph is incomplete.", truncated=True)
        edges = [edge for edge in self.edges.values()
                 if edge["source"] in self.units and edge["target"] in self.units]
        for edge in edges:
            if edge["origin"] == "enablement":
                self.units[edge["target"]]["enabled_by"].append(edge["source"])
        for name, unit in self.units.items():
            unit["aliases"] = sorted(alias for alias, target in self.aliases.items() if target == name)
            unit["enabled_by"] = sorted(set(unit["enabled_by"]))
            if unit["enabled_by"] and unit["load_state"] == "loaded":
                unit["unit_file_state"] = "enabled"
        default = self.resolve("default.target")
        cycles = _cycles(self.units, edges)
        if cycles:
            self.warn("Configured cycles are shown; dependency cycles alone do not establish a boot failure.")
        if len(cycles) >= 64:
            self.warn("Cycle listing is limited to 64 components.", truncated=True)
        return {"version": 1, "available": bool(self.fragments), "mode": "offline", "timing_available": False,
                "default_target": default[0] if self.units.get(default[0], {}).get("load_state") == "loaded" else None,
                "units": sorted(self.units.values(), key=lambda item: item["name"]),
                "edges": sorted(edges, key=lambda item: (item["source"], item["target"], item["relation"])),
                "aliases": {alias: target for alias, target in sorted(self.aliases.items()) if target in self.units},
                "cycles": cycles, "warnings": self.warnings,
                "truncated": self.truncated, "limits": dict(LIMITS)}


def _cycles(units, edges):
    """Iterative SCC traversal: cycles cannot recurse or explode the payload."""
    result = []
    for kind in ("ordering", "dependencies"):
        graph, inverse = defaultdict(set), defaultdict(set)
        for edge in edges:
            relation, source, target = edge["relation"], edge["source"], edge["target"]
            if kind == "ordering":
                if relation not in {"After", "Before"}:
                    continue
                if relation == "After":
                    source, target = target, source
            elif relation not in ACTIVATION:
                continue
            graph[source].add(target)
            inverse[target].add(source)
        seen, order = set(), []
        for name in sorted(units):
            if name in seen:
                continue
            seen.add(name)
            stack = [(name, iter(sorted(graph[name])))]
            while stack:
                node, children = stack[-1]
                child = next(children, None)
                if child is None:
                    order.append(node)
                    stack.pop()
                elif child not in seen:
                    seen.add(child)
                    stack.append((child, iter(sorted(graph[child]))))
        seen.clear()
        for name in reversed(order):
            if name in seen:
                continue
            component, pending = [], [name]
            seen.add(name)
            while pending:
                node = pending.pop()
                component.append(node)
                for parent in inverse[node] - seen:
                    seen.add(parent)
                    pending.append(parent)
            if len(component) > 1 or name in graph[name]:
                result.append({"kind": kind, "units": sorted(component)})
                if len(result) >= 64:
                    return result
    return result


def inspect_systemd(guest):
    """Inspect mounted system units without starting or running the guest."""
    return _Inspector(guest).inspect()
