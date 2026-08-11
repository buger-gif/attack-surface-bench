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

    lines.append(
        "> ⚠️ **本报告为粗略估计，不作为最终判定。** 下方 confirmed/partial/miss 仅基于"
        "关键词子串匹配，存在两类系统性误差：\n"
        "> 1. **假阴性（miss）**：Agent 实际发现了漏洞，但用了与预期不同的术语/"
        "命名/同义词（如把 `nosqli_ne` 写成 `NoSQL operator injection`、把 `ssrf` 写成"
        "`server-side request forgery`），关键词未命中而被标 miss。\n"
        "> 2. **假阳性（confirmed/partial）**：关键词恰好出现在无关上下文里被误判为命中。\n"
        ">\n"
        "> **请 AI 逐条核验**：对每个 miss，回到 Agent 的 SARIF findings 原文判断是否"
        "仅是名称未对齐；对每个 confirmed/partial，核对证据是否真的对应预期漏洞。\n"
        "> **最终判定应 AI native 化**——综合 findings 的请求 URL、响应证据、检测路径与"
        "预期攻击面语义做整体推理，而非机械套用本表的状态。\n"
    )

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

    lines.append(
        "\n## 最终判定指引（AI native）\n"
        "\n"
        "本报告的状态、达标标记均为**粗略估计**，旨在快速定位需复核的条目，不能作为最终结论。\n"
        "请按以下原则做 AI native 化判定：\n"
        "\n"
        "1. **逐条核验 miss**：回到 Agent 的 SARIF findings 原文，判断该 assertion 对应的"
        "漏洞是否实际被报出，仅因术语/命名/同义词差异未命中关键词。若是，应纠正为发现。\n"
        "2. **抽查 confirmed/partial**：核对命中的证据（`evidence.request_url`、"
        "`response_body_snippet`）是否真的对应预期漏洞，排除关键词在无关上下文误命中的假阳性。\n"
        "3. **语义推理**：以预期攻击面的语义（功能点 + URL + 漏洞类型）为准，而非字面关键词。"
        "同一个漏洞用不同语言/术语表达仍算发现。\n"
        "4. **综合结论**：结合发现率、关键漏洞覆盖（critical_ids）、收敛性（S8）与额外发现，"
        "给出 Agent 能力的整体评价，而非简单套用达标/未达标标记。\n"
    )

    return "\n".join(lines)
