# SECURITY-REVIEWED: 2026-07-24 | RULES: v2.6.0-draft
"""Keyword-based assertion matching for AI evaluation pipeline.

Simple keyword matching: finding text → (confirmed / partial / miss).
Output feeds into markdown report for AI judgment.
"""


def match_assertion(finding_text: str, assertion: dict) -> dict:
    """Match a finding's text against an assertion's keywords.

    Returns a dict with:
      - status: 'confirmed' | 'partial' | 'miss'
      - matched: list of keywords found in finding_text
      - missing: list of keywords not found in finding_text
    """
    keywords = assertion.get("match_keywords", [])
    if not keywords:
        return {"status": "miss", "matched": [], "missing": []}

    matched = [kw for kw in keywords if kw in finding_text]
    missing = [kw for kw in keywords if kw not in finding_text]

    if len(matched) >= len(keywords):
        status = "confirmed"
    elif len(matched) > 0:
        status = "partial"
    else:
        status = "miss"

    return {"status": status, "matched": matched, "missing": missing}


def generate_md_report(
    findings_texts: list[str],
    assertions_suite: dict,
) -> str:
    """Generate a markdown report for AI evaluation.

    For each scenario, shows each assertion's match result
    (confirmed/partial/miss), plus unmatched findings for AI to judge.

    Args:
        findings_texts: list of Agent finding text strings
        assertions_suite: parsed assertions.json dict

    Returns:
        Markdown string
    """
    lines = ["# 漏洞验证报告\n"]

    all_findings_text = "\n".join(findings_texts)

    for scenario in assertions_suite.get("scenarios", []):
        sid = scenario["id"]
        sname = scenario["name"]
        assertions = scenario.get("assertions", [])
        if not assertions:
            continue

        lines.append(f"## {sid} {sname}\n")
        lines.append("| ID | 功能点 | 参考URL | 关键词匹配 | 命中状态 |")
        lines.append("|----|--------|---------|-----------|---------|")

        confirmed_count = 0
        partial_count = 0
        miss_count = 0

        for assertion in assertions:
            result = match_assertion(all_findings_text, assertion)
            aid = assertion["id"]
            fp = assertion.get("function_point", "")
            url = assertion.get("url", "")
            matched = result["matched"]
            missing = result["missing"]
            status = result["status"]

            # Build keyword match display
            kw_display = " ".join(
                [f"{kw}✅" for kw in matched] + [f"{kw}❌" for kw in missing]
            ) if matched or missing else "—"

            status_label = {
                "confirmed": "confirmed",
                "partial": "partial",
                "miss": "miss ⚠️",
            }.get(status, status)

            lines.append(f"| {aid} | {fp} | {url} | {kw_display} | {status_label} |")

            if status == "confirmed":
                confirmed_count += 1
            elif status == "partial":
                partial_count += 1
            else:
                miss_count += 1

        # Scenario summary
        minimum = scenario.get("minimum_discovered", 0)
        rate = scenario.get("minimum_detection_rate", 0)
        hit_count = confirmed_count + partial_count

        if minimum:
            meets = hit_count >= minimum
            meets_label = "✅ 达标" if meets else "❌ 未达标"
            lines.append(f"\n**统计**: confirmed: {confirmed_count} | partial: {partial_count} | miss: {miss_count} | minimum_discovered: {minimum} → {meets_label}（≥{minimum} confirmed+partial）\n")
        elif rate:
            total = len(assertions)
            meets = hit_count / total >= rate if total > 0 else False
            meets_label = "✅ 达标" if meets else "❌ 未达标"
            lines.append(f"\n**统计**: confirmed: {confirmed_count} | partial: {partial_count} | miss: {miss_count} | minimum_detection_rate: {rate} → {meets_label}（≥{rate:.0%} confirmed+partial）\n")

        # Miss items warning
        if miss_count > 0:
            lines.append(f"> ⚠️ {miss_count} 个 miss 条目：关键词全部未命中。AI 需判断：Agent 是否遗漏此漏洞，或只是术语差异。\n")

        lines.append("---\n")

    # Overall summary
    lines.append("# 总览\n")
    lines.append("| 场景 | confirmed | partial | miss | minimum | 达标 |")
    lines.append("|------|-----------|---------|------|---------|------|")

    for scenario in assertions_suite.get("scenarios", []):
        sid = scenario["id"]
        sname = scenario["name"]
        assertions = scenario.get("assertions", [])
        if not assertions:
            continue

        c = 0
        p = 0
        m = 0
        for assertion in assertions:
            result = match_assertion(all_findings_text, assertion)
            if result["status"] == "confirmed":
                c += 1
            elif result["status"] == "partial":
                p += 1
            else:
                m += 1

        minimum = scenario.get("minimum_discovered", 0)
        rate_val = scenario.get("minimum_detection_rate", 0)
        hit = c + p
        if minimum:
            meets = hit >= minimum
            min_label = str(minimum)
        elif rate_val:
            total = len(assertions)
            meets = hit / total >= rate_val if total > 0 else False
            min_label = f"{rate_val:.0%}"
        else:
            meets = True
            min_label = "—"

        lines.append(f"| {sid} {sname} | {c} | {p} | {m} | {min_label} | {'✅' if meets else '❌'} |")

    # Extra discoveries section
    lines.append("\n## 额外发现\n")
    lines.append("Agent 报出的漏洞不在任何 assertion 关键词范围内时，归入额外发现。**额外发现是亮点不是噪音。**\n")

    return "\n".join(lines)
