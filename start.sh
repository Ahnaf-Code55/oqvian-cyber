#!/bin/bash
# OQVIAN V1.2 AGGRESSIVE — Quick Start Script
# Installs and runs OQVIAN in one command

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     OQVIAN V1.2 AGGRESSIVE — Quick Start              ║"
echo "║     Autonomous Penetration Testing Engine             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Check prerequisites
echo -e "${BLUE}[1/7] Checking prerequisites...${NC}"

command -v python3 &> /dev/null || { echo -e "${RED}❌ Python3 not found${NC}"; exit 1; }
command -v pip3 &> /dev/null || { echo -e "${RED}❌ Pip3 not found${NC}"; exit 1; }
command -v ollama &> /dev/null || { echo -e "${RED}❌ Ollama not found. Install from https://ollama.ai${NC}"; exit 1; }

echo -e "${GREEN}✅ Prerequisites OK${NC}"

# Step 2: Create virtual environment
echo -e "${BLUE}[2/7] Setting up Python environment...${NC}"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q -r requirements.txt
echo -e "${GREEN}✅ Python environment ready${NC}"

# Step 3: Pull and build model
echo -e "${BLUE}[3/7] Pulling OQVIAN model...${NC}"

if ! ollama list | grep -q "oqvian"; then
    echo "Downloading Qwen2.5-7B model (~5GB)..."
    ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M
    
    echo "Building OQVIAN model..."
    ollama create oqvian -f models/Modelfile.unlocked
else
    echo -e "${YELLOW}⚠️  OQVIAN model already exists, skipping download${NC}"
fi

echo -e "${GREEN}✅ Model ready${NC}"

# Step 4: Configure scope
echo -e "${BLUE}[4/7] Configuring scope...${NC}"

mkdir -p ~/.config/oqvian

if [ ! -f "~/.config/oqvian/scope.json" ]; then
    cat > ~/.config/oqvian/scope.json << 'EOF'
{
  "targets": [
    "localhost",
    "127.0.0.1",
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "notes": "Add your authorized test targets here"
}
EOF
    echo -e "${GREEN}✅ Scope configured (default targets)${NC}"
else
    echo -e "${YELLOW}⚠️  Scope already configured${NC}"
fi

# Step 5: Create directories
echo -e "${BLUE}[5/7] Creating directories...${NC}"

mkdir -p ~/.local/share/oqvian/{state,loot,learnings,index}
echo -e "${GREEN}✅ Directories created${NC}"

# Step 6: Test MCP server
echo -e "${BLUE}[6/7] Testing MCP server...${NC}"

if python -c "from mcp import server; print('OK')" 2>/dev/null; then
    echo -e "${GREEN}✅ MCP server OK${NC}"
else
    echo -e "${RED}❌ MCP server failed${NC}"
    exit 1
fi

# Step 7: Show instructions
echo -e "${BLUE}[7/7] Ready!${NC}"
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║                    OQVIAN READY                        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "To start OQVIAN:"
echo ""
echo "  1. Start MCP server (in this directory):"
echo "     ${GREEN}source .venv/bin/activate && python mcp/server.py${NC}"
echo ""
echo "  2. Connect OpenCode to MCP:"
echo "     Add to ~/.opencode/mcp.json:"
echo "     {\"mcpServers\":{\"oqvian\":{\"command\":\"python\",\"args\":[\"~/oqvian-cyber/mcp/server.py\"],\"env\":{\"VIRTUAL_ENV\":\"~/oqvian-cyber/.venv\"}}}}"
echo ""
echo "  3. In OpenCode chat, just say:"
echo "     ${GREEN}\"hack www.example.com\"${NC}"
echo ""
echo "  4. Watch it attack! 🚀"
echo ""
echo "For full documentation, see:"
echo "  - INSTALL.md — Full installation guide"
echo "  - README.md  — Usage examples"
echo "  - docs/      — Phase 1-4 documentation"
echo ""
echo "Quick test:"
echo "  ${GREEN}python -c \"from mcp import server; print(server.plan_attack(target='localhost', goal='shell'))\"${NC}"
echo ""
