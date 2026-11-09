# ✅ OQVIAN V1.2 AGGRESSIVE — RUNNING!

**Status**: Model loaded, MCP server starting  
**Time**: $(date)  
**User**: ifat

---

## What's Running

### 1. Ollama Server ✅
```bash
Location: /home/ifat/ollama
Version: 0.33.3
Status: Running (background)
```

### 2. OQVIAN Model ✅
```
Model: oqvian:latest
Size: 4.7 GB
Base: Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M
System Prompt: V1.2 AGGRESSIVE
Status: Loaded in Ollama
```

### 3. MCP Server 🔄
```
Command: python mcp/server.py
Location: /home/ifat/oqvian-cyber
Status: Starting (background)
Logs: /tmp/oqvian-mcp.log
```

### 4. Python Environment ✅
```
Virtual Env: /home/ifat/oqvian-cyber/.venv
Python: 3.x
Packages: mcp, numpy, httpx, aiohttp, cryptography, pydantic
Status: Ready
```

### 5. Configuration ✅
```
Scope: ~/.config/oqvian/scope.json
Targets: localhost, 192.168.1.0/24, 10.0.0.0/8, www.example.com
State: ~/.local/share/oqvian/state/
Loot: ~/.local/share/oqvian/loot/
Learnings: ~/.local/share/oqvian/learnings/
Audit: ~/.local/share/oqvian/audit.jsonl
```

---

## How to Use

### Option 1: Test Model Directly
```bash
export PATH="$HOME:$PATH"
ollama run oqvian "hack www.example.com"
```

### Option 2: Use MCP Server
```bash
cd /home/ifat/oqvian-cyber
source .venv/bin/activate
export PATH="$HOME:$PATH"

# Test MCP tools
python -c "
from mcp import server
print(server.plan_attack(target='localhost', goal='shell'))
"
```

### Option 3: Connect OpenCode
Add to `~/.opencode/mcp.json`:
```json
{
  "mcpServers": {
    "oqvian": {
      "command": "python",
      "args": ["/home/ifat/oqvian-cyber/mcp/server.py"],
      "env": {
        "VIRTUAL_ENV": "/home/ifat/oqvian-cyber/.venv",
        "PATH": "/home/ifat:$PATH"
      }
    }
  }
}
```

Then in OpenCode chat:
```
hack www.example.com
```

---

## Quick Commands

### Check Ollama Status
```bash
export PATH="$HOME:$PATH"
ollama list | grep oqvian
```

### Check MCP Server Logs
```bash
tail -f /tmp/oqvian-mcp.log
```

### Restart MCP Server
```bash
cd /home/ifat/oqvian-cyber
source .venv/bin/activate
export PATH="$HOME:$PATH"
pkill -f "python mcp/server.py"
python mcp/server.py
```

### Test Attack Planning
```bash
cd /home/ifat/oqvian-cyber
source .venv/bin/activate
python -c "from mcp import server; print(server.plan_attack(target='localhost', goal='shell'))"
```

### Run Autonomous Attack (Test)
```bash
cd /home/ifat/oqvian-cyber
source .venv/bin/activate
python -c "from mcp import server; print(server.autonomous_hack(target='localhost', scope='web', aggressiveness=3, timeout=30, verbose=False))"
```

---

## Memory Usage

```
RAM:  9.4 GB / 16 GB (6.6 GB free) ✅
GPU:  3.9 GB /  4 GB (0.1 GB free) ✅
```

---

## Next Steps

1. ✅ Model loaded in Ollama
2. ✅ MCP server started
3. ⏳ Test with: `ollama run oqvian "Who are you?"`
4. ⏳ Connect OpenCode to MCP
5. ⏳ Say "hack www.example.com" and watch!

---

**OQVIAN V1.2 AGGRESSIVE is running and ready to hack!** 🚀
