#!/usr/bin/env python3
"""Writes the SPDX 2.3 SBOM of a release from manifest.toml.

Generic scanners find nothing in the release archives: they have no
cataloger for Gleam, and the BEAM files carry no package metadata. The
locked Hex packages that ship (the runtime dependencies of gleam.toml, not
the dev ones) are listed with their checksums, plus the Erlang/OTP runtime
bundled in the Linux archives and packages.

    scripts/sbom.py VERSION > redirect-proxy-VERSION.spdx.json
"""

import datetime
import json
import pathlib
import sys
import tomllib
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO = "https://github.com/janalis/redirect-proxy"


def runtime_packages(project, manifest):
    """The locked packages reachable from the runtime dependencies."""
    by_name = {p["name"]: p for p in manifest["packages"]}
    pending = list(project.get("dependencies", {}))
    seen = {}
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        package = by_name[name]
        seen[name] = package
        pending.extend(package.get("requirements", []))
    return sorted(seen.values(), key=lambda p: p["name"])


def tool_version(tool):
    for line in (ROOT / ".tool-versions").read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == tool:
            return fields[1]
    raise SystemExit(f".tool-versions has no {tool} version")


def spdx_id(name):
    return "SPDXRef-Package-" + "".join(c if c.isalnum() else "-" for c in name)


def package(name, version, location, purl, checksum=None, licence="NOASSERTION"):
    entry = {
        "name": name,
        "SPDXID": spdx_id(name),
        "versionInfo": version,
        "downloadLocation": location,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": licence,
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }
    if checksum:
        entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum.lower()}]
    return entry


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__.strip().splitlines()[-1].strip())
    version = sys.argv[1]
    project = tomllib.loads((ROOT / "gleam.toml").read_text())
    manifest = tomllib.loads((ROOT / "manifest.toml").read_text())
    otp = tool_version("erlang")

    app = package(
        "redirect-proxy",
        version,
        f"{REPO}/releases/tag/v{version}",
        f"pkg:github/janalis/redirect-proxy@v{version}",
        licence=" AND ".join(project.get("licences", [])) or "NOASSERTION",
    )
    runtime = package(
        "erlang-otp",
        otp,
        f"https://github.com/erlang/otp/releases/tag/OTP-{otp}",
        f"pkg:github/erlang/otp@OTP-{otp}",
        licence="Apache-2.0",
    )
    dependencies = []
    for p in runtime_packages(project, manifest):
        if p.get("source") != "hex":
            raise SystemExit(f"{p['name']}: only Hex packages are supported")
        dependencies.append(
            package(
                p["name"],
                p["version"],
                f"https://repo.hex.pm/tarballs/{p['name']}-{p['version']}.tar",
                f"pkg:hex/{p['name']}@{p['version']}",
                checksum=p.get("outer_checksum"),
            )
        )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"redirect-proxy-{version}",
        "documentNamespace": f"{REPO}/releases/v{version}/sbom-{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "creators": ["Tool: redirect-proxy scripts/sbom.py"],
        },
        "packages": [app, runtime, *dependencies],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": app["SPDXID"],
            },
            *(
                {
                    "spdxElementId": app["SPDXID"],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": d["SPDXID"],
                }
                for d in [runtime, *dependencies]
            ),
        ],
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
