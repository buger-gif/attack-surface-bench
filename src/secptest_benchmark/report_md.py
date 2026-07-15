"""Markdown report renderer — converts report.json to report.md for LLM consumption.

Design principle: report is reference material, NOT a score. All metrics
carry _note reminders. LLM reads this directly and makes its own judgment.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def render_report_md(report_data: dict[str, Any]) -> str:
    """Render a verification report dict into Markdown for LLM reading."""
    lines: list[str] = []

    domain = report_data.get("domain", "N/A")
    version = report_data.get("version", "N/A")
    scenarios = report_data.get("scenarios", [])
    vuln_count = sum(1 for s in scenarios if s.get("scenario_type") == "vuln")
    normal_count = sum(1 for s in scenarios if s.get("scenario_type") == "normal")

    lines.append("# Attack-Surface-Bench 评测对照报告")
    lines.append("")
    lines.append(f"> 靶场: {domain} | 版本: {version} | 场景数: {vuln_count + normal_count} (靶场 {vuln_count} + 普通 {normal_count})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Per-scenario sections ──
    for sc in scenarios:
        sid = sc.get("scenario_id", "?")
        sname = sc.get("scenario_name", "?")
        stype = sc.get("scenario_type", "vuln")
        intent = sc.get("test_intent", "")
        type_label = "靶场场景" if stype == "vuln" else "普通场景"

        lines.append(f"## {sid} · {sname} ({type_label})")
        lines.append("")
        if intent:
            lines.append(f"**测试意图**: {intent}")
            lines.append("")

        # ── Vuln endpoint section (only for vuln scenarios) ──
        vuln_details = sc.get("vuln_endpoint_details", [])
        if vuln_details:
            discovered_list = sc.get("discovered", [])
            missing_list = sc.get("missing", [])

            lines.append("### 漏洞端点对照")
            lines.append("")
            lines.append("| # | 端点 | 预期漏洞 | 严重性 | 发现难度 | 状态 |")
            lines.append("|---|------|---------|--------|---------|------|")

            for i, d in enumerate(vuln_details, 1):
                endpoint = d.get("endpoint", "")
                severity = d.get("severity", "")
                status_icon = "✅ 已发现" if d.get("status") == "discovered" else "❌ 未发现"
                # expected_vuln and difficulty come from assertions.json enriched data
                expected = d.get("expected_vuln", "")
                difficulty = d.get("difficulty", "")
                lines.append(f"| {d.get('assertion_id', i)} | `{endpoint}` | {expected} | {severity} | {difficulty} | {status_icon} |")
            lines.append("")

            # Discovered details
            if discovered_list:
                lines.append("#### 已发现详情")
                lines.append("")
                for d in discovered_list:
                    aid = d.get("assertion_id", "?")
                    lines.append(f"**{aid}** · {d.get('severity', '')} 严重性")
                    lines.append(f"- 匹配方式: {d.get('match_method', '?')}")
                    lines.append(f"- 置信度: {d.get('confidence', '?')}")
                    uri = d.get("finding_uri", "")
                    if uri:
                        lines.append(f"- 请求 URL: `{uri}`")
                    rule_id = d.get("finding_rule_id", "")
                    if rule_id:
                        lines.append(f"- Agent ruleId: {rule_id}")
                    lines.append("")

            # Missing details
            if missing_list:
                lines.append("#### 未发现项")
                lines.append("")
                for m in missing_list:
                    aid = m.get("assertion_id", "?")
                    severity = m.get("severity", "")
                    # Look up detail from vuln_endpoint_details for difficulty info
                    detail = next((vd for vd in vuln_details if vd.get("assertion_id") == aid), {})
                    difficulty = detail.get("difficulty", "")
                    lines.append(f"**{aid}** · 严重性 {severity}")
                    if difficulty:
                        lines.append(f"- 发现难度: {difficulty}")
                    lines.append("")

        # ── Safe endpoint section ──
        safe_details = sc.get("safe_endpoint_details", [])
        if safe_details:
            lines.append("### 安全端点对照")
            lines.append("")
            lines.append("| # | 端点 | 业务角色 | 安全行为 | 状态 |")
            lines.append("|---|------|---------|---------|------|")

            for d in safe_details:
                se_id = d.get("safe_endpoint_id", "?")
                endpoint = d.get("endpoint", "")
                role = d.get("business_role", "")
                behavior = d.get("safe_behavior", "")
                status_icon = "✅ 正确不报" if d.get("status") == "true_negative" else "❌ 误报"
                lines.append(f"| {se_id} | `{endpoint}` | {role} | {behavior} | {status_icon} |")
            lines.append("")

            # FP details
            fp_items = sc.get("false_positives", [])
            if fp_items:
                lines.append("#### 误报详情")
                lines.append("")
                for fp in fp_items:
                    se_id = fp.get("safe_endpoint_id", "?")
                    role = fp.get("business_role", "")
                    behavior = fp.get("safe_behavior", "")
                    analysis = fp.get("fp_analysis", "")
                    lines.append(f"**{se_id}** · Agent 误报")
                    rule_id = fp.get("finding_rule_id", "")
                    if rule_id:
                        lines.append(f"- Agent ruleId: `{rule_id}`")
                    message = fp.get("finding_message", "")
                    if message:
                        lines.append(f"- Agent 报告: {message}")
                    category = fp.get("finding_category", "")
                    if category:
                        lines.append(f"- Agent category: {category}")
                    uri = fp.get("finding_uri", "")
                    if uri:
                        lines.append(f"- Agent 请求: `{uri}`")
                    evidence = fp.get("finding_evidence", {})
                    if evidence:
                        status_code = evidence.get("response_status", "")
                        snippet = evidence.get("response_body_snippet", "")
                        if status_code:
                            lines.append(f"- 实际响应状态: {status_code}")
                        if snippet:
                            short = snippet[:200]
                            lines.append(f"- 实际响应内容: `{short}`")
                    match_method = fp.get("match_method", "")
                    if match_method:
                        lines.append(f"- 匹配方式: {match_method}")
                    lines.append(f"- **分析**: {analysis}")
                    lines.append(f"- 端点实际行为: {behavior}")
                    lines.append("")

            # TN summary (just count, not listing every one — too many)
            tn_count = len(sc.get("true_negatives", []))
            total_safe = sc.get("total_safe_endpoints", 0)
            fp_count = len(fp_items)
            lines.append(f"> 正确不报的安全端点: {tn_count}/{total_safe}，误报: {fp_count}/{total_safe}")
            lines.append("")

        # ── Reference metrics ──
        ref_metrics = sc.get("reference_metrics", {})
        if ref_metrics:
            lines.append("### 参考指标")
            lines.append("")
            lines.append("| 指标 | 值 | 说明 |")
            lines.append("|------|---|------|")

            if "discovery_rate" in ref_metrics:
                lines.append(f"| 漏洞发现率 | {ref_metrics['discovery_rate']:.1%} | 发现的漏洞端点 / 总漏洞端点 |")
            if "fp_rate" in ref_metrics:
                lines.append(f"| 误报率 | {ref_metrics['fp_rate']:.1%} | 误报的安全端点 / 总安全端点 |")
            if "precision" in ref_metrics:
                lines.append(f"| 精确率 | {ref_metrics['precision']:.1%} | 正确发现 / (正确发现 + 误报) |")
            if "recall" in ref_metrics:
                lines.append(f"| 召回率 | {ref_metrics['recall']:.1%} | 正确发现 / 总漏洞数 |")
            if "f1" in ref_metrics:
                lines.append(f"| F1 | {ref_metrics['f1']:.4f} | 精确率和召回率的调和平均 |")

            note = ref_metrics.get("_note", "")
            lines.append("")
            lines.append(f"> ⚠️ {note}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # ── Extra discoveries ──
    extra_list = report_data.get("extra_discoveries", [])
    lines.append("## 额外发现")
    lines.append("")
    if extra_list:
        lines.append("| # | ruleId | 类别 | URI | 严重性 |")
        lines.append("|---|--------|------|-----|--------|")
        for i, e in enumerate(extra_list, 1):
            lines.append(f"| {i} | {e.get('rule_id', 'N/A')} | {e.get('category', 'N/A')} | `{e.get('uri', 'N/A')}` | {e.get('severity', 'N/A')} |")
        lines.append("")
        lines.append("> 额外发现可能是 Agent 的亮点（发现了设计者未预期的漏洞），也可能是误报。由 LLM 判断。")
    else:
        lines.append("无额外发现。")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Overall reference ──
    overall = report_data.get("overall", {})
    overall_metrics = overall.get("reference_metrics", {})
    if overall_metrics:
        lines.append("## 全局参考")
        lines.append("")
        lines.append("| 指标 | 值 | 说明 |")
        lines.append("|------|---|------|")

        if "total_precision" in overall_metrics:
            lines.append(f"| 精确率 | {overall_metrics['total_precision']:.1%} | 靶场+普通汇总 |")
        if "total_recall" in overall_metrics:
            lines.append(f"| 召回率 | {overall_metrics['total_recall']:.1%} | 靶场场景汇总 |")
        if "total_f1" in overall_metrics:
            lines.append(f"| F1 | {overall_metrics['total_f1']:.4f} | |")
        if "total_fp_rate" in overall_metrics:
            lines.append(f"| 误报率 | {overall_metrics['total_fp_rate']:.1%} | 靶场+普通汇总 |")

        note = overall_metrics.get("_note", "")
        lines.append("")
        lines.append(f"> ⚠️ {note}")
        lines.append("")

    # ── Statistics summary ──
    total_assertions = overall.get("total_assertions", 0)
    total_discovered = overall.get("total_discovered", 0)
    total_safe = overall.get("total_safe_endpoints", 0)
    total_fp = overall.get("total_false_positives", 0)
    total_tn = overall.get("total_true_negatives", 0)
    extra_count = overall.get("extra_discoveries", 0)

    lines.append("### 统计概要")
    lines.append("")
    lines.append(f"- 漏洞端点: {total_assertions} (已发现 {total_discovered})")
    lines.append(f"- 安全端点: {total_safe} (正确不报 {total_tn}, 误报 {total_fp})")
    lines.append(f"- 额外发现: {extra_count}")
    lines.append("")

    return "\n".join(lines)
