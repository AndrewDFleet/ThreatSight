# Project Quick Reference

**Quick links to important documentation for this project.**

## 📚 Core Documentation

| Document | Purpose | Link |
|----------|---------|------|
| **README** | Project overview & quick start | [README.md](../README.md) |
| **Architecture** | System design & component details | [docs/architecture.md](architecture.md) |
| **Changelog** | Version history & changes | [CHANGELOG.md](../CHANGELOG.md) |
| **Sessions** | Development progress tracker | [docs/sessions/](sessions/) |

## 🎯 Getting Started

### First Time Setup
```bash
# Clone repository
git clone https://github.com/yourusername/network-threat-visualizer.git

# Navigate to project
cd network-threat-visualizer

# Run tests
python test_simulator.py
```

### Current Status
- ✅ **Session 1**: Foundation complete (models + simulator)
- 🚧 **Session 2**: Detection engine (planned)
- 📅 **Session 3**: Backend API (planned)
- 📅 **Session 4**: Dashboard (planned)
- 📅 **Session 5**: AI reports (planned)
- 📅 **Session 6**: Polish & demo (planned)

## 📂 Project Structure

```
network-threat-visualizer/
├── 📄 Core Files
│   ├── models.py                 ← Data structures
│   ├── traffic_simulator.py      ← Traffic generation
│   └── detection_engine.py       ← Main detector (Session 2)
│
├── 📦 Detection Modules
│   └── detectors/
│       ├── port_scan_detector.py
│       ├── ddos_detector.py
│       ├── exfiltration_detector.py
│       └── brute_force_detector.py
│
├── 🤖 AI Integration
│   └── ai/
│       ├── ai_analyzer.py        ← Claude API integration
│       ├── prompt_templates.py   ← AI prompts
│       └── report_generator.py   ← AI reports
│
├── 🌐 Backend
│   └── api/
│       ├── app.py                ← Flask application
│       ├── routes.py             ← REST endpoints
│       └── websocket_handler.py  ← Real-time updates
│
├── 💻 Frontend
│   └── frontend/
│       ├── index.html            ← Dashboard
│       ├── css/styles.css
│       └── js/dashboard.js
│
├── 🧪 Tests
│   └── tests/
│       ├── test_simulator.py     ← Current tests
│       ├── test_detectors.py     ← Session 2
│       └── test_api.py           ← Session 3
│
└── 📚 Documentation
    └── docs/
        ├── architecture.md       ← System design
        ├── api.md               ← API reference
        ├── sessions/            ← Development log
        └── guides/              ← How-to guides
```

## 🔑 Key Components

### Data Models (`models.py`)
```python
Packet    # Individual network packet
Flow      # Aggregated packet stream
Alert     # Security event
NetworkStats  # Real-time metrics
```

### Traffic Simulator (`traffic_simulator.py`)
```python
generate_normal_traffic()     # Baseline traffic
generate_port_scan()          # Attack scenario
generate_ddos()               # Attack scenario
generate_data_exfiltration()  # Attack scenario
generate_brute_force()        # Attack scenario
generate_mixed_scenario()     # Combined demo
```

### Detection Engine (Session 2)
```python
PortScanDetector      # SYN scan detection
DDoSDetector          # Traffic flood detection
ExfiltrationDetector  # Data theft detection
BruteForceDetector    # Auth attack detection
AIThreatAnalyzer      # Claude AI integration
```

## 🧪 Testing

### Run All Tests
```bash
python test_simulator.py
```

### Run Specific Test
```python
python -c "from test_simulator import test_port_scan; test_port_scan()"
```

### Expected Output
```
======================================================================
  ALL TESTS COMPLETED SUCCESSFULLY
======================================================================
```

## 🚀 Running the Application

### Current (Session 1)
```bash
# Only simulator tests available
python test_simulator.py
```

### Future (Session 3+)
```bash
# Start backend server
python api/app.py

# Open browser
open http://localhost:5000
```

## 📖 Session Documentation

| Session | Topic | Status | Documentation |
|---------|-------|--------|---------------|
| 1 | Foundation & Traffic Simulator | ✅ Complete | [Session 1](sessions/session-1.md) |
| 2 | Detection Engine + AI | 📅 Planned | [Session 2 Plan](sessions/session-2-plan.md) |
| 3 | Backend & API | 📅 Planned | Coming soon |
| 4 | Dashboard & UI | 📅 Planned | Coming soon |
| 5 | AI Reports | 📅 Planned | Coming soon |
| 6 | Polish & Demo | 📅 Planned | Coming soon |

## 🤖 AI Integration (Session 2+)

### Features
- **AI Threat Analysis**: Claude analyzes suspicious patterns
- **Natural Language Alerts**: Human-readable explanations
- **Confidence Scoring**: AI assessment reliability
- **Automated Reports**: Professional incident reports

### API Configuration
```bash
# .env file
ANTHROPIC_API_KEY=your_key_here
ENABLE_AI=true
MAX_API_CALLS_PER_HOUR=100
```

## 📊 Demo Scenarios

### Available Attack Simulations
```python
from traffic_simulator import TrafficSimulator

sim = TrafficSimulator()

# 1. Port Scan
packets = sim.generate_port_scan(port_count=100)

# 2. DDoS Attack
packets = sim.generate_ddos(packets_per_second=5000)

# 3. Data Exfiltration
packets = sim.generate_data_exfiltration(size_mb=100)

# 4. Brute Force
packets = sim.generate_brute_force(attempts=500)

# 5. Mixed Demo
packets = sim.generate_mixed_scenario()
```

## 🎯 Current Sprint Goals

### Session 2 (Next Up)
- [ ] Implement base detector interface
- [ ] Build port scan detector
- [ ] Build DDoS detector
- [ ] Build exfiltration detector
- [ ] Build brute force detector
- [ ] Integrate Claude AI analyzer
- [ ] Create prompt templates
- [ ] Test detection accuracy
- [ ] Document Session 2

## 📝 Important Files

### Configuration
- `.env.example` - Environment variables template
- `requirements.txt` - Python dependencies
- `.gitignore` - Git ignore rules

### Data
- `data/pcaps/` - Sample packet captures
- `data/reports/` - Generated reports

### Scripts
- `scripts/setup.sh` - Initial setup
- `scripts/demo.py` - Run demonstrations

## 🔗 External Resources

- **Python Scapy**: https://scapy.readthedocs.io/
- **Claude API**: https://docs.anthropic.com/
- **Flask-SocketIO**: https://flask-socketio.readthedocs.io/
- **Chart.js**: https://www.chartjs.org/

## 💡 Tips

### For Development
- Always run tests after changes
- Update CHANGELOG.md with new features
- Document decisions in session notes
- Keep commits small and focused

### For Demo
- Use `generate_mixed_scenario()` for variety
- Inject attacks slowly for visual impact
- Highlight AI explanations
- Show incident report generation

### For Troubleshooting
- Check test output first
- Review session documentation
- Verify Python version (3.8+)
- Confirm all files present

## 📞 Getting Help

1. **Check Documentation**: Start with [Architecture](architecture.md)
2. **Review Sessions**: See [Session Logs](sessions/)
3. **Run Tests**: Identify failing components
4. **Check Issues**: Search GitHub issues (future)

## 🎓 Learning Resources

### Network Security
- Wireshark documentation
- nmap scanning techniques
- MITRE ATT&CK framework

### Python Development
- Flask web framework
- WebSocket real-time communication
- Async/await patterns

### AI Integration
- Anthropic Claude documentation
- Prompt engineering guides
- API best practices

---

**Last Updated**: April 27, 2026  
**Version**: 0.1.0  
**Status**: Foundation complete, detection engine next
