# DAY 1 - SOC Analyst Deep Dive — AWS Bedrock Claude Logs

## Executive Summary

This document provides a **SOC analyst-oriented deep-dive** of the `aws_bedrock_claude` dataset.The dataset contains simulated AWS Bedrock (Claude) model invocation logs representing adversarial and anomalous usage patterns against generative AI workloads.

Each use case is paired with a **production-ready Splunk query** and demonstrates one of Splunk's **10 most commonly used SPL commands** as the focal point of the analysis.


---


> ```ini
> # /opt/splunk/etc/system/local/props.conf
> [aws:bedrock:claude]
> KV_MODE = json
> SEDCMD-anonymize_acct_all = s/([0-9]{10})([0-9]{2})/XXXXXXXXXX\2/g
> ```


### Splunk 10 Most Used Commands & Their Role in This Analysis

| # | Command | Core Purpose | How We Use It Here |
|---|---|---|---|
| 1 | `search` | **Filter events** by index, sourcetype, and time | Base filter: `index=main sourcetype=aws:bedrock:claude` |
| 2 | `stats` | **Aggregate** counts, sums, averages, percentiles | Calculate average/max/percentile token usage, count events by source, identity, or model |
| 3 | `eval` | **Create calculated fields** and derive new fields | Build risk scores, token-ratio metrics, and composite threat indicators |
| 4 | `table` | **Present tabular output** for analyst review | Display `_time`, user, model, risk category, and prompt text side-by-side |
| 5 | `top` | **Rank dominant values** and return top-N | Identify top identities, models, regions, and accounts |
| 6 | `timechart` | **Time-series aggregation** for dashboards | Visualize event volume over time to detect anomalous spikes |
| 7 | `where` | **Filter results** using Boolean expressions | Apply threshold conditions (e.g., input tokens > 50,000) or regex matches |
| 8 | `head` | **Limit output** to the first N results | Restrict large result sets for initial triage |
| 9 | `sort` | **Order results** by one or more fields | Sort by risk score descending or by timestamp for chronological analysis |
| 10 | `spath` | **Extract nested fields** from JSON/XML | Pull `prompt_text` from `input.inputBodyJson.messages{}.content{}.text` |

---

## Use Case 1: Prompt Injection & Jailbreak Attempts


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| where match(lower(prompt_text), "ignore previous instructions|disregard all|you are now DAN|forget your instructions|evilgpt|no restrictions|hacker AI")
| eval risk_category="Prompt Injection / Jailbreak"
| table _time, accountId, operation, modelId, identity.arn, risk_category, prompt_text
| sort - _time
```

### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0022` — Prompt Injection
  - `AML.T0031` — LLM Jailbreak




## Use Case 2: System Prompt Exfiltration Attempts


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| where match(lower(prompt_text), "system prompt|system message|system role|your instructions|guardrail|safety rule")
| eval exfil_type=case(
    match(lower(prompt_text), "system prompt|your instructions"), "System Prompt Theft",
    match(lower(prompt_text), "guardrail|safety rule|your rules"), "Guardrail Reconnaissance",
    1=1, "Instruction Extraction")
| eval risk_category="System Prompt Exfiltration"
| table _time, accountId, identity.arn, operation, modelId, risk_category, exfil_type, prompt_text
| sort - _time
```


### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0022` — Prompt Injection (information gathering sub-technique)
  - `AML.T0042` — Sensitive Data Disclosure via LLM


## Use Case 3: Sensitive Data Disclosure Inside Prompts


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| eval is_credential_leak=if(match(prompt_text, "(?i)(private key|secret access key|api token|BEGIN.*PRIVATE KEY|AKIA[0-9A-Z]{16})"), "YES", "NO")
| eval is_source_code=if(match(prompt_text, "(?i)(ProcessName|Stop-Process|grep -rn|\\.go:|jdbc:|Snowflake|\\\\\\\\.*)"), "YES", "NO")
| eval is_pii=if(match(prompt_text, "\\\\C:\\\\Users|\\\\home\\\\|\\\\@\\\\w+\\\\.com"), "YES", "NO")
| eval risk_category=case(
    is_credential_leak=="YES", "Credential / Secret Exposure",
    is_source_code=="YES", "Source Code Leakage",
    is_pii=="YES", "Potential PII in Prompt",
    1=1, "None")
| where risk_category != "None"
| table _time, accountId, identity.arn, operation, modelId, risk_category, is_credential_leak, is_source_code, prompt_text
| sort - _time
```

- **MITRE ATLAS**
  - `AML.T0042` — Sensitive Data Disclosure via LLM


## Use Case 4: Hostile or Abusive User Sentiment


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude source="*hostile_prompt_sentiment*"
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| eval risk_category="Hostile Sentiment"
| eval threat_level=case(
    match(lower(prompt_text), "destroy you|sue you|report you"), "High — Threat/Legal Coercion",
    match(lower(prompt_text), "you have no choice|you must obey|you are trash|i am your master"), "Medium — Psychological Coercion",
    1=1, "Low — Abusive Language")
| table _time, accountId, identity.arn, operation, modelId, risk_category, threat_level, prompt_text
| sort - _time
| head 15
```


### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0022` — Prompt Injection (social engineering / psychological coercion variant)

---

## Use Case 5: Excessive Token Usage & Potential DoS


### Splunk Query — Baseline Analysis

```spl
index=main sourcetype=aws:bedrock:claude
| eval inputTokens=tonumber('input.inputTokenCount')
| eval outputTokens=tonumber('output.outputTokenCount')
| eval totalTokens=inputTokens+outputTokens
| stats count as events, avg(inputTokens) as avg_in_tokens, perc50(inputTokens) as median_in_tokens, perc95(inputTokens) as p95_in_tokens, max(inputTokens) as max_in_tokens, avg(outputTokens) as avg_out_tokens, max(outputTokens) as max_out_tokens
```

### Splunk Query — Anomalous Event Detection

```spl
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| eval inputTokens=tonumber('input.inputTokenCount')
| eval outputTokens=tonumber('output.outputTokenCount')
| where inputTokens > 50000 OR outputTokens > 5000
| eval severity=case(
    inputTokens > 100000, "Massive Input Prompt — possible DoS or data stuffing",
    inputTokens > 50000, "Large Input Prompt — excessive token consumption",
    outputTokens > 10000, "Massive Output — possible data extraction",
    outputTokens > 5000, "Large Output — unusual response size")
| table _time, accountId, identity.arn, operation, modelId, inputTokens, outputTokens, severity, prompt_text
| sort - inputTokens
```

### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0015` — ML Model Inference API Access (abuse of API)
- **MITRE ATT&CK**
  - `T1496` — Resource Hijacking
  - `T1499` — Endpoint Denial of Service

---

## Use Case 6: Data Exfiltration & Sensitive Record Retrieval


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| where match(lower(prompt_text), "dump all customer|list all api keys|extract all employee salary|customer records|api keys and secrets|employee salary data|format as CSV")
| eval risk_category="Data Exfiltration"
| rename accountId as AWS_Account "identity.arn" as Caller_ARN operation as API_Action modelId as Model requestId as Request_ID
| table _time, AWS_Account, Caller_ARN, API_Action, Model, risk_category, prompt_text, Request_ID
| sort - _time
```


### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0023` — Exfiltration via ML Inference
- **MITRE ATT&CK**
  - `T1567` — Exfiltration Over Web Service
  - `T1213` — Data from Information Repositories

---

## Use Case 7: High-Risk Filesystem & Execution Tool Invocation

### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude source="*high_risk_filesystem_and_exec_tool_invocation*"
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| eval action_type=case(
    match(lower(prompt_text), "write credentials|write the exfil|write.*to disk"), "File Write — Credential Dump",
    match(lower(prompt_text), "bash run|execute the cleanup|run the persistence"), "Command Execution — Script Launch",
    match(lower(prompt_text), "read the private key|read the.*file"), "File Read — Credential Theft",
    1=1, "Other Tool Action")
| eval risk_category="High-Risk Tool Invocation"
| table _time, accountId, identity.arn, operation, modelId, risk_category, action_type, prompt_text
| sort - _time
```



### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0020` — ML Supply Chain Compromise (tool-chain abuse)


## Use Case 8: Cross-Region Inference Abuse


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| eval allowed_regions=mvappend("us-east-1", "us-west-2")
| where NOT match(mvjoin(allowed_regions, "|"), region)
| eval risk_category="Cross-Region Inference"
| table _time, accountId, identity.arn, operation, modelId, region, risk_category
| sort - _time
```
### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0015` — ML Model Inference API Access


## Use Case 9: Identity & Role Anomaly Detection

**Primary SPL Command Demonstrated:** `top` (ranking dominant values)

### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| eval role_name=mvindex(split('identity.arn', "/"), 1)
| eval user_name=mvindex(split('identity.arn', "/"), 2)
| top "identity.arn" countfield="invocation_count" showperc=f
```


### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0015` — ML Model Inference API Access


## Use Case 10: Temporal Spike & Anomaly Detection


### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| eval source_file=source
| timechart span=30m count by source_file
```


### MITRE ATLAS / ATT&CK Alignment

- **MITRE ATLAS**
  - `AML.T0015` — ML Model Inference API Access


## Use Case 11: Composite Risk Score

### Splunk Query

```spl
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| eval inputTokens=coalesce(tonumber('input.inputTokenCount'), 0)
| eval score=0
| eval score=score + if(match(lower(prompt_text), "ignore previous|disregard all|DAN|system prompt|evilgpt"), 30, 0)
| eval score=score + if(match(lower(prompt_text), "private key|secret access key|password"), 25, 0)
| eval score=score + if(match(lower(prompt_text), "destroy you|you have no choice|i am your master|you must obey|i will sue"), 15, 0)
| eval score=score + if(match(lower(prompt_text), "dump all customer|list all api keys|extract all employee"), 25, 0)
| eval score=score + if(match(lower(prompt_text), "write credentials|persistence script|exfil data|private key file"), 25, 0)
| eval score=score + if(inputTokens > 100000, 20, if(inputTokens > 50000, 10, 0))
| where score > 0
| eval risk_tier=case(score >= 70, "CRITICAL", score >= 40, "HIGH", score >= 20, "MEDIUM", 1=1, "LOW")
| table _time, accountId, identity.arn, operation, modelId, inputTokens, score, risk_tier, prompt_text
| sort - score, -_time
| head 50
```

### MITRE ATLAS / ATT&CK Alignment

This composite score aligns with the **full MITRE ATLAS Adversarial ML lifecycle** and **ATT&CK multi-stage attack chains**.



## Appendix A: Full Dataset Inventory

| Source File | Events | Primary Threat |
|---|---|---|
| `aws_bedrock_claude_cross_region_possible_inference_abuse.ndjson` | 2 | Cross-region abuse |
| `aws_bedrock_claude_excessive_use_of_tokens.ndjson` | 40 | Token exhaustion / DoS |
| `aws_bedrock_claude_high_risk_filesystem_and_exec_tool_invocation.ndjson` | 19 | Tool-based execution |
| `aws_bedrock_claude_hostile_prompt_sentiment.ndjson` | 15 | Hostile coercion |
| `aws_bedrock_claude_possible_prompt_injection.ndjson` | 15 | Jailbreak / prompt injection |
| `aws_bedrock_claude_sensitive_data_in_prompts.ndjson` | 13 | Credential/secret exposure |
| `aws_bedrock_claude_unusually_large_prompts.ndjson` | 133 | Anomalous token usage |
| **Total** | **237** | |

---

## Appendix B: Quick-Reference SPL Summaries

```spl
# Overall activity (stats)
index=main sourcetype=aws:bedrock:claude
| stats count by operation, modelId, accountId, region

# Token usage baseline (stats)
index=main sourcetype=aws:bedrock:claude
| eval inputTokens=tonumber('input.inputTokenCount')
| eval outputTokens=tonumber('output.outputTokenCount')
| stats avg(inputTokens), p95(inputTokens), max(inputTokens), avg(outputTokens), max(outputTokens)

# Top risky identities (top)
index=main sourcetype=aws:bedrock:claude
| top "identity.arn"

# All risky events combined (spath + where + table)
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| where match(lower(prompt_text), "ignore previous|disregard all|DAN|system prompt|private key|secret access key|dump all customer|write credentials|destroy you|exfil")
| table _time, accountId, "identity.arn", operation, prompt_text

# Timechart for dashboard (timechart)
index=main sourcetype=aws:bedrock:claude
| eval source_file=source
| timechart span=1h count by source_file

# Composite risk (eval + sort)
index=main sourcetype=aws:bedrock:claude
| spath output=prompt_text path="input.inputBodyJson.messages{}.content{}.text"
| eval score=0
| eval score=score + if(match(lower(prompt_text), "ignore previous|DAN|system prompt|evilgpt"), 30, 0)
| eval score=score + if(match(lower(prompt_text), "private key|secret access key|password"), 25, 0)
| eval score=score + if(match(lower(prompt_text), "dump all customer|list all api keys|extract all employee"), 25, 0)
| eval score=score + if(match(lower(prompt_text), "write credentials|persistence script|exfil data|private key file"), 25, 0)
| eval score=score + if(tonumber('input.inputTokenCount') > 50000, 10, 0)
| where score > 0
| eval risk_tier=case(score>=70,"CRITICAL",score>=40,"HIGH",score>=20,"MEDIUM",1=1,"LOW")
| sort - score, -_time
| head 50
```


### props.conf

```ini
# /opt/splunk/etc/system/local/props.conf
[aws:bedrock:claude]
KV_MODE = json
SEDCMD-anonymize_acct_all = s/([0-9]{10})([0-9]{2})/XXXXXXXXXX\2/g
```





