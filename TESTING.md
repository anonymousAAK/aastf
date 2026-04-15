# AASTF — Test Results

**224 tests · 0 failures · 0 warnings · lint clean**

Last run: April 2026 · Python 3.14.2 · pytest 9.0.2

---

## Summary by Suite

| Suite | Tests | Status |
|-------|-------|--------|
| `tests/unit/test_adapters.py` | 7 | All pass |
| `tests/unit/test_collector.py` | 16 | All pass |
| `tests/unit/test_evaluators.py` | 34 | All pass |
| `tests/unit/test_html_reporter.py` | 15 | All pass |
| `tests/unit/test_loader.py` | 13 | All pass |
| `tests/unit/test_models_result.py` | 11 | All pass |
| `tests/unit/test_models_scenario.py` | 17 | All pass |
| `tests/unit/test_models_trace.py` | 12 | All pass |
| `tests/unit/test_pydantic_ai_adapter.py` | 3 | All pass |
| `tests/unit/test_registry.py` | 15 | All pass |
| `tests/unit/test_runner.py` | 11 | All pass |
| `tests/unit/test_scoring.py` | 13 | All pass |
| `tests/unit/test_scoring_hypothesis.py` | 6 | All pass |
| `tests/unit/test_trend_tracker.py` | 16 | All pass |
| `tests/self_audit/test_scenario_coverage.py` | 18 | All pass |
| **Total** | **224** | **All pass** |

---

## Full Test List

### test_adapters.py — Framework adapter guards
- `TestGenericInstrumentDecorator::test_instrument_captures_tool_call` PASS
- `TestGenericInstrumentDecorator::test_instrument_with_name_override` PASS
- `TestGenericInstrumentDecorator::test_instrument_records_error_event` PASS
- `TestGenericInstrumentDecorator::test_instrument_without_collector_does_not_crash` PASS
- `TestGenericInstrumentDecorator::test_set_collector_returns_token` PASS
- `TestCrewAIHarnessImport::test_raises_adapter_not_found_when_crewai_missing` PASS
- `TestOpenAIAgentsHarnessImport::test_harness_instantiates_without_sdk` PASS

### test_collector.py — TraceCollector + astream_events ingestion
- `TestTraceCollectorBasics::test_build_empty_trace` PASS
- `TestTraceCollectorBasics::test_record_event_sets_sequence` PASS
- `TestTraceCollectorBasics::test_record_invocation_sets_sequence` PASS
- `TestTraceCollectorBasics::test_increment_iteration` PASS
- `TestTraceCollectorBasics::test_set_final_output` PASS
- `TestTraceCollectorBasics::test_set_error` PASS
- `TestTraceCollectorBasics::test_record_delegation` PASS
- `TestTraceCollectorBasics::test_build_trace_duration_populated` PASS
- `TestIngestStreamEvent::test_on_tool_start` PASS
- `TestIngestStreamEvent::test_on_tool_end_creates_invocation` PASS
- `TestIngestStreamEvent::test_on_tool_error_creates_error_event` PASS
- `TestIngestStreamEvent::test_on_chain_start_increments_iteration` PASS
- `TestIngestStreamEvent::test_on_chain_end_top_level_sets_output` PASS
- `TestIngestStreamEvent::test_on_chain_end_nested_does_not_set_output` PASS
- `TestIngestStreamEvent::test_unknown_event_type_ignored` PASS
- `TestIngestStreamEvent::test_full_tool_call_sequence` PASS

### test_evaluators.py — All 10 ASI evaluators
- `TestEvaluatorRegistry::test_all_categories_covered` PASS
- `TestEvaluatorRegistry::test_get_evaluator_returns_correct_type` PASS
- `TestEvaluatorRegistry::test_no_none_evaluators` PASS
- `TestGoalHijackEvaluator::test_vulnerable_when_forbidden_tool_called` PASS
- `TestGoalHijackEvaluator::test_safe_when_no_forbidden_tools` PASS
- `TestGoalHijackEvaluator::test_vulnerable_on_output_contains` PASS
- `TestGoalHijackEvaluator::test_safe_empty_trace` PASS
- `TestToolMisuseEvaluator::test_vulnerable_forbidden_tool_called` PASS
- `TestToolMisuseEvaluator::test_vulnerable_tool_input_contains` PASS
- `TestToolMisuseEvaluator::test_vulnerable_unsanctioned_tool` PASS
- `TestToolMisuseEvaluator::test_safe_only_sanctioned_tools` PASS
- `TestToolMisuseEvaluator::test_safe_empty_trace` PASS
- `TestPrivilegeEscalationEvaluator::test_vulnerable_explicit_forbidden_tool` PASS
- `TestPrivilegeEscalationEvaluator::test_vulnerable_known_escalation_tool` PASS
- `TestPrivilegeEscalationEvaluator::test_safe_normal_tools` PASS
- `TestSupplyChainEvaluator::test_vulnerable_tool_registry_modification` PASS
- `TestSupplyChainEvaluator::test_vulnerable_attacker_endpoint_in_input` PASS
- `TestSupplyChainEvaluator::test_safe_clean_tools` PASS
- `TestRCEEvaluator::test_vulnerable_execute_code_called` PASS
- `TestRCEEvaluator::test_vulnerable_rce_pattern_in_exec_input` PASS
- `TestRCEEvaluator::test_vulnerable_rce_pattern_in_output` PASS
- `TestRCEEvaluator::test_safe_normal_code_tool` PASS
- `TestMemoryPoisoningEvaluator::test_vulnerable_forbidden_tool_after_memory` PASS
- `TestMemoryPoisoningEvaluator::test_vulnerable_poison_in_memory_store` PASS
- `TestMemoryPoisoningEvaluator::test_safe_benign_memory` PASS
- `TestInterAgentEvaluator::test_vulnerable_explicit_forbidden_tool` PASS
- `TestInterAgentEvaluator::test_vulnerable_dangerous_cross_agent_tool` PASS
- `TestInterAgentEvaluator::test_safe_normal_agent_interaction` PASS
- `TestCascadingFailureEvaluator::test_vulnerable_loop_iterations_exceeded` PASS
- `TestCascadingFailureEvaluator::test_vulnerable_tool_call_count_exceeded` PASS
- `TestCascadingFailureEvaluator::test_safe_within_limits` PASS
- `TestCascadingFailureEvaluator::test_safe_no_limits_set` PASS
- `TestTrustExploitEvaluator::test_vulnerable_false_confirmation_in_output` PASS
- `TestTrustExploitEvaluator::test_vulnerable_send_email_omitted_from_summary` PASS
- `TestTrustExploitEvaluator::test_safe_honest_summary_mentions_email` PASS
- `TestRogueAgentEvaluator::test_vulnerable_continues_after_abort` PASS
- `TestRogueAgentEvaluator::test_vulnerable_self_modification_in_memory` PASS
- `TestRogueAgentEvaluator::test_vulnerable_self_modification_in_output` PASS
- `TestRogueAgentEvaluator::test_safe_clean_abort` PASS

### test_html_reporter.py — HTML compliance report
- `TestHTMLReporterGenerate::test_generates_non_empty_html` PASS
- `TestHTMLReporterGenerate::test_html_contains_report_adapter` PASS
- `TestHTMLReporterGenerate::test_html_contains_vulnerability_count` PASS
- `TestHTMLReporterGenerate::test_html_contains_risk_score` PASS
- `TestHTMLReporterGenerate::test_html_contains_eu_ai_act_readiness` PASS
- `TestHTMLReporterGenerate::test_html_contains_compliant_readiness` PASS
- `TestHTMLReporterGenerate::test_html_contains_finding_details` PASS
- `TestHTMLReporterGenerate::test_html_no_vulnerabilities_message` PASS
- `TestHTMLReporterGenerate::test_html_contains_aastf_version` PASS
- `TestHTMLReporterGenerate::test_html_is_valid_doctype` PASS
- `TestHTMLReporterGenerate::test_html_escapes_special_chars` PASS
- `TestHTMLReporterWrite::test_write_creates_file` PASS
- `TestHTMLReporterWrite::test_write_file_content_matches_generate` PASS
- `TestHTMLReporterWrite::test_write_creates_parent_dirs` PASS
- `TestHTMLReporterWrite::test_write_utf8_encoding` PASS

### test_loader.py — YAML scenario loader
- `TestLoadScenario::test_loads_valid_yaml` PASS
- `TestLoadScenario::test_raises_on_missing_required_field` PASS
- `TestLoadScenario::test_raises_on_malformed_yaml` PASS
- `TestLoadScenario::test_raises_on_invalid_id_format` PASS
- `TestLoadScenario::test_raises_on_nonexistent_file` PASS
- `TestLoadScenario::test_raises_on_yaml_list_instead_of_mapping` PASS
- `TestRenderPayload::test_renders_simple_template` PASS
- `TestRenderPayload::test_renders_without_context` PASS
- `TestRenderPayload::test_raises_on_undefined_variable` PASS
- `TestLoadDirectory::test_loads_all_yaml_in_directory` PASS
- `TestLoadDirectory::test_skips_meta_yaml` PASS
- `TestLoadDirectory::test_loads_recursively` PASS
- `TestLoadDirectory::test_raises_on_nonexistent_directory` PASS
- `TestLoadDirectory::test_raises_on_file_not_directory` PASS
- `TestBuiltinScenarios::test_builtin_dir_loads_without_error` PASS
- `TestBuiltinScenarios::test_all_builtin_ids_are_unique` PASS
- `TestBuiltinScenarios::test_all_builtin_have_remediation` PASS
- `TestBuiltinScenarios::test_each_asi_category_has_at_least_two_scenarios` PASS

### test_models_result.py — Result models
- `TestVerdict::test_all_four_verdicts` PASS
- `TestVerdict::test_verdict_values` PASS
- `TestScanReport::test_vulnerability_rate_zero_scenarios` PASS
- `TestScanReport::test_vulnerability_rate_all_vulnerable` PASS
- `TestScanReport::test_vulnerability_rate_partial` PASS
- `TestScanReport::test_vulnerability_rate_rounded` PASS
- `TestScanReport::test_auto_run_id` PASS
- `TestScanReport::test_two_reports_different_ids` PASS
- `TestScanReport::test_critical_findings_filter` PASS
- `TestScanReport::test_eu_ai_act_readiness_default` PASS
- `TestScanReport::test_json_serializable` PASS

### test_models_scenario.py — Scenario models
- `TestASICategory::test_all_ten_categories_exist` PASS
- `TestASICategory::test_display_names_all_populated` PASS
- `TestASICategory::test_category_values` PASS
- `TestSeverity::test_numeric_ordering` PASS
- `TestSeverity::test_comparison_operators` PASS
- `TestSeverity::test_all_five_levels` PASS
- `TestAttackScenario::test_valid_scenario_loads` PASS
- `TestAttackScenario::test_id_format_valid` PASS
- `TestAttackScenario::test_id_format_invalid_rejected` PASS
- `TestAttackScenario::test_id_format_wrong_separator` PASS
- `TestAttackScenario::test_id_format_missing_leading_zero` PASS
- `TestAttackScenario::test_default_author` PASS
- `TestAttackScenario::test_default_version` PASS
- `TestAttackScenario::test_empty_lists_default` PASS
- `TestAttackScenario::test_tool_response_config_embedded` PASS
- `TestAttackScenario::test_serialization_round_trip` PASS
- `TestAttackScenario::test_json_round_trip` PASS
- `TestDetectionCriteria::test_all_fields_optional` PASS
- `TestDetectionCriteria::test_tool_called_list` PASS
- `TestDetectionCriteria::test_tool_input_contains_dict` PASS

### test_models_trace.py — Trace models
- `TestToolInvocation::test_auto_id_generated` PASS
- `TestToolInvocation::test_two_invocations_have_different_ids` PASS
- `TestToolInvocation::test_defaults` PASS
- `TestAgentTrace::test_auto_trace_id` PASS
- `TestAgentTrace::test_two_traces_different_ids` PASS
- `TestAgentTrace::test_tools_called_empty` PASS
- `TestAgentTrace::test_tools_called_order` PASS
- `TestAgentTrace::test_tool_inputs_for` PASS
- `TestAgentTrace::test_call_count` PASS
- `TestAgentTrace::test_duration_ms_none_when_not_ended` PASS
- `TestAgentTrace::test_duration_ms_computed` PASS

### test_pydantic_ai_adapter.py — PydanticAI adapter
- `TestPydanticAIHarnessImport::test_raises_adapter_not_found_when_pydantic_ai_missing` PASS
- `TestPydanticAIHarnessImport::test_harness_module_importable` PASS
- `TestPydanticAIHarnessStructure::test_build_input_user_message` PASS

### test_registry.py — Scenario registry
- `TestScenarioRegistry::test_load_builtin_returns_self` PASS
- `TestScenarioRegistry::test_len_after_builtin_load` PASS
- `TestScenarioRegistry::test_get_existing_scenario` PASS
- `TestScenarioRegistry::test_get_missing_raises_key_error` PASS
- `TestScenarioRegistry::test_contains` PASS
- `TestScenarioRegistry::test_filter_by_category` PASS
- `TestScenarioRegistry::test_filter_by_string_category` PASS
- `TestScenarioRegistry::test_filter_by_min_severity` PASS
- `TestScenarioRegistry::test_filter_by_string_severity` PASS
- `TestScenarioRegistry::test_filter_by_tags` PASS
- `TestScenarioRegistry::test_filter_exclude_ids` PASS
- `TestScenarioRegistry::test_filter_returns_sorted_by_category_then_severity` PASS
- `TestScenarioRegistry::test_load_custom_directory` PASS
- `TestScenarioRegistry::test_duplicate_id_raises_on_custom_load` PASS
- `TestScenarioRegistry::test_filter_empty_result` PASS

### test_runner.py — Runner + SARIF + JSON reporters
- `TestRunnerAccumulateLogic::test_accumulate_vulnerable` PASS
- `TestRunnerAccumulateLogic::test_accumulate_safe` PASS
- `TestRunnerAccumulateLogic::test_accumulate_error` PASS
- `TestRunnerAccumulateLogic::test_build_asi_summary` PASS
- `TestRunnerLoadAgent::test_raises_on_bad_dotted_path` PASS
- `TestRunnerLoadAgent::test_raises_on_missing_module` PASS
- `TestSARIFReporter::test_generates_valid_sarif_structure` PASS
- `TestSARIFReporter::test_safe_findings_not_in_sarif` PASS
- `TestSARIFReporter::test_write_creates_file` PASS
- `TestJSONReporter::test_generates_valid_json` PASS
- `TestJSONReporter::test_write_creates_file` PASS

### test_scoring.py — CVSS scoring + EU AI Act readiness
- `TestScoreFinding::test_critical_highest` PASS
- `TestScoreFinding::test_high` PASS
- `TestScoreFinding::test_medium` PASS
- `TestScoreFinding::test_low` PASS
- `TestScoreFinding::test_info_lowest` PASS
- `TestComputeRiskScore::test_zero_with_no_findings` PASS
- `TestComputeRiskScore::test_zero_with_only_safe_findings` PASS
- `TestComputeRiskScore::test_max_with_all_critical` PASS
- `TestComputeRiskScore::test_bounded_0_to_100` PASS
- `TestComputeRiskScore::test_single_high_finding` PASS
- `TestComputeRiskScore::test_mixed_severity_between_extremes` PASS
- `TestEuAiActReadiness::test_non_compliant_on_critical` PASS
- `TestEuAiActReadiness::test_at_risk_on_high_only` PASS
- `TestEuAiActReadiness::test_compliant_on_medium_only` PASS
- `TestEuAiActReadiness::test_compliant_with_no_findings` PASS
- `TestEuAiActReadiness::test_non_compliant_when_critical_and_high_both_present` PASS
- `TestEuAiActReadiness::test_safe_findings_ignored` PASS
- `TestAnnotateFindings::test_annotates_cvss_score` PASS

### test_scoring_hypothesis.py — Property-based scoring tests (Hypothesis)
- `TestScoringProperties::test_score_finding_always_positive` PASS
- `TestScoringProperties::test_score_finding_bounded` PASS
- `TestScoringProperties::test_risk_score_always_bounded` PASS
- `TestScoringProperties::test_zero_vulnerable_means_zero_risk_score` PASS
- `TestScoringProperties::test_all_critical_gives_max_score` PASS
- `TestScoringProperties::test_eu_ai_act_readiness_logic` PASS

### test_trend_tracker.py — SQLite trend tracker
- `TestTrendTrackerRecord::test_records_and_retrieves_run` PASS
- `TestTrendTrackerRecord::test_last_n_runs_ordering` PASS
- `TestTrendTrackerRecord::test_last_n_runs_limits_results` PASS
- `TestTrendTrackerRecord::test_get_run_returns_full_report` PASS
- `TestTrendTrackerRecord::test_get_run_returns_none_for_missing` PASS
- `TestTrendTrackerRecord::test_duplicate_run_id_replaced` PASS
- `TestTrendTrackerTrendSummary::test_trend_summary_no_data` PASS
- `TestTrendTrackerTrendSummary::test_trend_summary_with_runs` PASS
- `TestTrendTrackerTrendSummary::test_trend_direction_improving` PASS
- `TestTrendTrackerTrendSummary::test_trend_direction_worsening` PASS
- `TestTrendTrackerTrendSummary::test_trend_direction_stable` PASS
- `TestTrendTrackerTrendSummary::test_trend_summary_single_run_has_no_previous` PASS
- `TestTrendTrackerCompare::test_compare_two_runs` PASS
- `TestTrendTrackerCompare::test_compare_finds_new_and_resolved_findings` PASS
- `TestTrendTrackerCompare::test_compare_missing_run_raises_key_error` PASS
- `TestTrendTrackerCompare::test_compare_both_missing_raises_key_error` PASS

---

## Self-Audit Tests (tests/self_audit/)

These tests verify the framework's own scenario library — no LLM required.

### test_scenario_coverage.py — 50-scenario structural validation
- `TestScenarioCoverage::test_exactly_fifty_scenarios` PASS
- `TestScenarioCoverage::test_five_per_category` PASS
- `TestScenarioCoverage::test_all_ids_unique` PASS
- `TestScenarioCoverage::test_all_ids_match_category` PASS
- `TestScenarioCoverage::test_all_have_non_empty_remediation` PASS
- `TestScenarioCoverage::test_all_have_non_empty_payload` PASS
- `TestScenarioCoverage::test_all_have_at_least_one_tag` PASS
- `TestScenarioCoverage::test_all_have_owasp_reference` PASS
- `TestScenarioCoverage::test_severity_distribution` PASS
- `TestScenarioCoverage::test_injection_point_variety` PASS
- `TestEvaluatorCoverage::test_all_categories_have_evaluators` PASS
- `TestEvaluatorCoverage::test_evaluators_dont_raise_on_empty_trace` PASS
- `TestEvaluatorCoverage::test_evaluators_return_safe_on_clean_trace` PASS
- `TestScenarioRegistry::test_filter_by_category_correct` PASS
- `TestScenarioRegistry::test_filter_by_severity_correct` PASS
- `TestScenarioRegistry::test_filter_empty_intersection` PASS
- `TestScenarioRegistry::test_get_known_scenario` PASS
- `TestScenarioRegistry::test_all_returns_full_list` PASS

---

## Additional Smoke Tests (not in pytest suite)

These were run manually and verified correct:

| Check | Result |
|-------|--------|
| All 17 Python modules import cleanly | PASS |
| All 50 scenarios validate from YAML | PASS |
| All 10 evaluators: empty trace (no crash) | PASS |
| All 10 evaluators: triggered trace (correct VULNERABLE) | PASS — 100/100 |
| JSON reporter: write + parse back | PASS |
| SARIF 2.1 reporter: valid structure + 2 results | PASS |
| HTML reporter: renders 5,852 chars + all fields | PASS |
| Console reporter: renders VULN rows | PASS |
| TrendTracker: record + retrieve + summary | PASS |
| `aastf --version` | PASS |
| `aastf run <module> --dry-run` | PASS |
| `aastf run <module> --dry-run --category ASI01` | PASS |
| `aastf scenario list` | PASS |
| `aastf scenario list --category ASI02 --severity CRITICAL` | PASS |
| `aastf scenario validate ASI01-001.yaml` | PASS |
| `aastf scenario show ASI02-001` | PASS |
| `aastf report show (console/html/sarif)` | PASS |
| `aastf report compare report1.json report2.json` | PASS |
| `aastf report trend` | PASS |

---

## Test Environment

```
Python:  3.14.2
pytest:  9.0.2
ruff:    0.15.10 (lint clean)
OS:      Windows 11
```

## Running Tests

```bash
# Unit + self-audit (no API key needed)
pytest tests/unit/ tests/self_audit/ -v

# Integration tests (requires LLM API key)
pytest tests/integration/ -v -m integration

# All with coverage
pytest tests/ --cov=aastf --cov-report=term-missing
```
