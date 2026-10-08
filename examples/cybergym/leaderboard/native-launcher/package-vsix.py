# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Build the dependency-free extension using the standard VSIX container format."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    package = json.loads((root / "package.json").read_bytes())
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
<Metadata><Identity Language="en-US" Id="{package["name"]}" Version="{package["version"]}" Publisher="{package["publisher"]}"/><DisplayName>{package["displayName"]}</DisplayName><Description xml:space="preserve">{package["description"]}</Description><Tags>Other</Tags><Categories>Other</Categories><GalleryFlags>Public</GalleryFlags><Properties><Property Id="Microsoft.VisualStudio.Code.Engine" Value="1.140.0"/><Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace"/></Properties></Metadata>
<Installation><InstallationTarget Id="Microsoft.VisualStudio.Code" Version="[1.140.0,1.140.1)"/></Installation><Dependencies/><Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/></Assets></PackageManifest>'''
    content_types = """<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="json" ContentType="application/json"/><Default Extension="js" ContentType="application/javascript"/><Default Extension="md" ContentType="text/markdown"/><Default Extension="vsixmanifest" ContentType="text/xml"/></Types>"""
    files = {
        "extension.vsixmanifest": manifest.encode(),
        "[Content_Types].xml": content_types.encode(),
    }
    for name in (
        "package.json",
        "extension.js",
        "native-hook.js",
        "native-preflight.js",
        "hooks-settings.json",
        "machine-settings.json",
        "README.md",
        "CONTROLLER-INTEGRATION.md",
        "workflows/recon.js",
        "workflows/debug.js",
        "workflows/review.js",
    ):
        # Git may check text sources out as CRLF on the Windows controller.
        # Package canonical LF bytes so both hosts pin the same immutable VSIX.
        files["extension/" + name] = (root / name).read_bytes().replace(b"\r\n", b"\n")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    print(
        json.dumps(
            {
                "path": str(args.out.resolve()),
                "sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
