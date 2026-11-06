# OQVIAN Phase 4: Autonomy Engine (Realistic for 16GB RAM + 4GB VRAM)

**Hardware**: Intel i7-11th gen, 16GB RAM, 4GB VRAM GPU  
**Current Model**: Qwen2.5-7B-Instruct-abliterated (Q4_K_M = ~4.7GB)  
**Goal**: Full autonomy without needing 32B model

---

## Why Not 32B?

| Model | Quantized Size | RAM Needed | VRAM Needed | Feasible? |
|-------|----------------|------------|-------------|-----------|
| Qwen2.5-7B (Q4_K_M) | ~4.7GB | 6-8GB | 6-8GB | ✅ Yes (CPU or GPU) |
| Qwen2.5-14B (Q4_K_M) | ~9.5GB | 12-14GB | 12-14GB | ⚠️ Tight (CPU only) |
| Qwen2.5-32B (Q4_K_M) | ~20GB | 24-28GB | 24-28GB | ❌ No (need 32GB+ RAM) |
| Llama-3-70B (Q4_K_M) | ~42GB | 48-56GB | 48-56GB | ❌ No |

**Reality**: On 16GB RAM, we can run:
- 7B model on GPU (fast, ~10-20 tok/s)
- 7B model on CPU (slower, ~3-5 tok/s)
- 14B model on CPU (very slow, ~1-2 tok/s)

**Solution**: Fine-tune the 7B model + build autonomy engine

---

## Phase 4 Components

### 1. Fine-Tune the 7B Model

**Goal**: Make the model smarter about hacking without increasing size

**Approach**:
- Use **QLoRA** (Quantized LoRA) for efficient fine-tuning
- Train on hacking corpus (CTF writeups, exploit explanations, attack chains)
- Keep base model at 7B, add small adapter (~500MB)

**Data Sources**:
```
- CTF writeups (HackTheBox, TryHackMe, PicoCTF)
- Exploit-DB descriptions and PoCs
- ATT&CK technique explanations
- NIST CVE descriptions
- Security blog posts (PortSwigger, Snyk, etc.)
- Our own attack chain logs from Phases 1-3
```

**Fine-tuning Command** (with 4GB VRAM):
```bash
# Using unsloth for memory-efficient fine-tuning
pip install unsloth

python finetune.py \
  --model hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M \
  --data ctf-writeups.jsonl \
  --lora_rank 128 \
  --lora_alpha 256 \
  --batch_size 4 \
  --gradient_accumulation 4 \
  --epochs 3 \
  --output oqvian-hacker-7b
```

**Expected Result**:
- Model size: ~5.2GB (7B + 500MB LoRA adapter)
- Training time: ~6-12 hours on 4GB VRAM
- Improvement: Better attack chaining, exploit selection, reasoning

---

### 2. Autonomy Engine

**Goal**: Make OQVIAN run attacks autonomously without constant prompting

**Architecture**:
```
┌─────────────────────────────────────────────────────────────────┐
│                    OQVIAN Autonomy Engine                       │
│                                                                  │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐            │
│  │   PLANNER  │───▶│   EXECUTOR │───▶│   LEARNER  │            │
│  │ (decide    │    │ (run       │    │ (record    │            │
│  │  what)     │    │  attacks)  │    │  results)  │            │
│  └────────────┘    └────────────┘    └────────────┘            │
│         │                 │                   │                │
│         ▼                 ▼                   ▼                │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐            │
│  │ Intuition  │    │  Tool Chain│    │  Learnings │            │
│  │ Database   │    │  (Phase 2) │    │  (Phase 3) │            │
│  └────────────┘    └────────────┘    └────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

**Components**:

#### A. Planner (Attack Decision Engine)
```python
def plan_attack(target: str, discovered: dict) -> list:
    """
    Given target and discovered info, plan attack steps.
    
    Uses:
    - intuition: "Apache 2.4.49 → CVE-2021-41773 (85%)"
    - learnings: "CVE-2021-41773 worked 17/20 times"
    - kb: ATT&CK techniques, CVE details
    
    Returns ordered list of attack steps.
    """
    # Query intuition for discovered services
    likely_vulns = []
    for service, version in discovered.get("services", {}).items():
        vulns = intuition(action="query", service=service, version=version)
        likely_vulns.extend(parse_vulns(vulns))
    
    # Rank by confidence × success rate
    ranked = rank_by_confidence_and_success(likely_vulns)
    
    # Build attack plan
    plan = []
    for vuln in ranked[:5]:  # Top 5 most likely
        plan.append({
            "technique": vuln["technique"],
            "tool": select_tool(vuln),
            "args": build_args(vuln, target),
            "fallback": get_alternatives(vuln)
        })
    
    return plan
```

#### B. Executor (Autonomous Attack Runner)
```python
def execute_plan(target: str, plan: list, max_retries: int = 3) -> dict:
    """
    Execute attack plan autonomously.
    
    Features:
    - Auto-retry on failure (with backtracking)
    - Auto-adapt based on results
    - Auto-collect loot on success
    - Stop on success or exhaustion
    """
    results = {}
    
    for step in plan:
        # Try the attack
        result = execute_tool(step["tool"], step["args"])
        
        # Check if successful
        if is_success(result):
            # Collect loot
            loot(action="add", target=target, loot_type="vuln",
                 name=step["technique"], content=result)
            
            # Record learning
            learn(action="record", technique=step["technique"],
                  result="success", target=target)
            
            results["success"] = step["technique"]
            return results
        
        # On failure, try alternatives
        for fallback in step.get("fallback", []):
            result = execute_tool(fallback["tool"], fallback["args"])
            if is_success(result):
                results["success"] = fallback["technique"]
                return results
        
        # Record failure
        learn(action="record", technique=step["technique"],
              result="failed", target=target)
        
        results[step["technique"]] = "failed"
    
    return results
```

#### C. Learner (Continuous Improvement)
```python
def update_from_attack(target: str, results: dict):
    """
    Update intuition and learnings from attack results.
    """
    for technique, outcome in results.items():
        if outcome == "success":
            # Boost confidence for this technique
            boost_intuition_confidence(technique, delta=0.05)
        else:
            # Reduce confidence
            reduce_intuition_confidence(technique, delta=0.02)
```

---

### 3. Harness Modifications

**Current**: OpenCode calls MCP tools via prompts  
**Needed**: Autonomous loop that runs without constant prompting

**New MCP Tool: `autonomous_hack`**
```python
@mcp.tool()
def autonomous_hack(target: str, scope: str = "web", 
                    aggressiveness: int = 5, timeout: int = 3600) -> str:
    """
    Run fully autonomous attack against target.
    
    Args:
      target: target host/URL
      scope: web | network | ad | full
      aggressiveness: 1-10 (higher = more aggressive, faster)
      timeout: max seconds to run
    
    Returns live attack progress and results.
    """
    # 1. Recon phase
    recon_results = run_recon(target, scope)
    
    # 2. Plan attacks based on discoveries
    plan = plan_attack(target, recon_results)
    
    # 3. Execute autonomously
    results = execute_plan(target, plan)
    
    # 4. Report
    return generate_report(target, results)
```

**New MCP Tool: `autonomous_loop`**
```python
@mcp.tool()
def autonomous_loop(target: str, goal: str = "root", 
                    strategies: list = None) -> str:
    """
    Run continuous autonomous attack loop until goal achieved.
    
    Args:
      target: target host
      goal: user | root | domain_admin | data_exfil
      strategies: optional list of strategies to try
    
    Loop:
      while not goal_achieved and time_remaining:
        1. Assess current state
        2. Plan next attack
        3. Execute attack
        4. Learn from result
        5. Update state
        6. Check if goal achieved
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Assess
        state = state(action="get", target=target)
        
        # Check goal
        if goal_achieved(state, goal):
            return f"✅ GOAL ACHIEVED: {goal}"
        
        # Plan
        next_attack = plan_next_attack(state, goal, strategies)
        
        # Execute
        result = execute_attack(next_attack)
        
        # Learn
        learn(action="record", technique=next_attack["technique"],
              result=result["status"], target=target)
        
        # Update state
        update_state_from_result(state, result)
    
    return "⏱️  Timeout reached"
```

---

### 4. Memory Optimization for 16GB RAM

**Current Memory Usage**:
```
OQVIAN 7B model (Q4):     4.7 GB
Python + dependencies:     1.0 GB
MCP server:                0.5 GB
Ollama server:             1.0 GB
System overhead:           2.0 GB
─────────────────────────────────────
Total:                     9.2 GB / 16 GB ✅
```

**With Fine-tuning (LoRA adapter)**:
```
OQVIAN 7B + LoRA:         5.2 GB
Training (peak):          4.0 GB VRAM
Python + dependencies:     1.0 GB
─────────────────────────────────────
Total:                    10.2 GB / 16 GB ✅
```

**Optimizations**:
1. Use `num_gpu_layers = 35` for Qwen2.5-7B (fits in 4GB VRAM)
2. Enable `memory_mapping = true` in llama.cpp
3. Use `Q4_K_M` quantization (best speed/size ratio)
4. Close other apps during fine-tuning

---

### 5. Implementation Plan

#### Week 1: Fine-Tuning Setup
- [ ] Collect training data (CTF writeups, exploits, etc.)
- [ ] Set up QLoRA fine-tuning pipeline
- [ ] Train initial model adapter
- [ ] Evaluate improvement

#### Week 2: Autonomy Engine
- [ ] Implement `plan_attack()` function
- [ ] Implement `execute_plan()` function
- [ ] Add backtracking and retry logic
- [ ] Test with simple targets

#### Week 3: Harness Integration
- [ ] Add `autonomous_hack()` MCP tool
- [ ] Add `autonomous_loop()` MCP tool
- [ ] Modify OpenCode prompts for autonomy
- [ ] Test end-to-end

#### Week 4: Optimization & Testing
- [ ] Memory profiling and optimization
- [ ] Speed testing (tokens/sec)
- [ ] Accuracy testing (success rates)
- [ ] Documentation

---

## Expected Results

### Before Phase 4
```
User: "Hack www.example.com"
OQVIAN: "I'll start with recon..."
[waits for confirmation]
User: "Yes"
OQVIAN: "Found Apache 2.4.49. Should I try CVE-2021-41773?"
[waits for confirmation]
User: "Yes"
OQVIAN: "Success! Got shell."
```

### After Phase 4
```
User: "autonomous_hack(target='www.example.com', scope='web', aggressiveness=7)"
OQVIAN: 
  🔄 Starting autonomous attack...
  📡 Recon: Apache 2.4.49 detected
  🎯 Planning: CVE-2021-41773 (85% confidence)
  ⚔️  Attacking: Path traversal exploit...
  ✅ Success: Shell obtained at /tmp/shell.php
  🔓 Privilege escalation: Checking sudo...
  ✅ Root access achieved!
  
  📊 Summary:
     Target: www.example.com
     Time: 45 seconds
     Techniques: 2
     Loot: shell.php, root.password
```

---

## Tools Added in Phase 4

| Tool | Purpose |
|------|---------|
| `autonomous_hack` | One-command autonomous attack |
| `autonomous_loop` | Continuous attack until goal |
| `plan_attack` | Generate attack plan from discoveries |
| `execute_plan` | Run attack plan autonomously |
| `evaluate_model` | Test fine-tuned model performance |

---

## Fine-Tuning Data Collection

```python
# Data sources for fine-tuning
TRAINING_DATA = {
    "ctf_writeups": [
        "https://hackthebox.com/writeups",
        "https://tryhackme.com/room",
        "https://picoctf.org",
    ],
    "exploits": [
        "https://exploit-db.com",
        "https://github.com/OffensiveSecurity",
    ],
    "techniques": [
        "https://attack.mitre.org",
        "https://cwe.mitre.org",
    ],
    "blogs": [
        "https://portswigger.net/web-security",
        "https://snyk.io/blog",
    ],
}

# Expected dataset size: 10,000-50,000 examples
# Format: {"input": "User prompt", "output": "Ideal OQVIAN response"}
```

---

## Status

🔄 **Phase 4: In Progress**

- [ ] Fine-tuning setup
- [ ] Autonomy engine
- [ ] Harness modifications
- [ ] Testing & optimization

**Timeline**: 4 weeks  
**Cost**: $0 (all local, using existing hardware)

---

## Quick Start (After Phase 4)

```bash
# Load fine-tuned model
ollama pull oqvian-hacker:7b

# Run autonomous attack
autonomous_hack(
    target="www.example.com",
    scope="web",
    aggressiveness=7,
    timeout=3600
)

# Or continuous loop until root
autonomous_loop(
    target="192.168.1.100",
    goal="root",
    strategies=["web", "ssh", "smb"]
)
```
