"""Built-in sample plugin.

Demonstrates the plugin protocol by appending a small provenance marker to a
finding's evidence field. It does not change severity, CVSS, or any other
field — purely additive.
"""

from __future__ import annotations

from ..core.models import Finding


class SamplePlugin:
    name = "sample"
    description = "Adds a GuardScope provenance marker to a finding's evidence."

    def enrich(self, finding: Finding) -> Finding:
        marker = "[guardscope:sample-plugin]"
        if marker not in finding.evidence:
            finding.evidence = (finding.evidence + "\n" + marker).strip()
        return finding