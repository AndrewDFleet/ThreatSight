# Session 2 Plan: Detection Engine + AI Integration

**Status**: 📅 Planned (Not Yet Started)  
**Estimated Duration**: 3-4 hours  
**Prerequisites**: Session 1 complete, Claude API key obtained  

## Objectives

Build intelligent threat detection system combining traditional rule-based algorithms with AI-powered analysis:

1. Implement traditional detectors for each attack type
2. Integrate Claude AI for contextual analysis
3. Create detection pipeline that combines both approaches
4. Test and tune detection accuracy
5. Generate enhanced alerts with AI explanations

## Components to Build

### 1. Base Detector Interface (`detectors/base_detector.py`)

Abstract class defining detector contract:

```python
class BaseDetector(ABC):
    """
    Abstract base class for all detectors
    """
    
    @abstractmethod
    def analyze(self, packets: List[Packet], 
                flows: List[Flow]) -> List[Alert]:
        """
        Analyze traffic and return alerts
        """
        pass
    
    @abstractmethod
    def get_baseline_stats(self) -> dict:
        """
        Get normal baseline for this detector
        """
        pass
    
    def update_baseline(self, packets: List[Packet]):
        """
        Update baseline based on normal traffic
        """
        pass
```

**Why Abstract Class**:
- Consistent interface for all detectors
- Easy to add new detection types
- Testable in isolation
- Composable in pipeline

### 2. Port Scan Detector (`detectors/port_scan_detector.py`)

**Detection Algorithm**:
```python
# Identify port scans by:
# 1. Count unique ports per source->destination pair
# 2. Check for sequential port patterns
# 3. Detect SYN flags without ACK (SYN scan)
# 4. Fast timing between attempts

Thresholds:
- unique_ports > 50: MEDIUM
- unique_ports > 100: HIGH  
- sequential + SYN flags: CRITICAL
```

**Features**:
- Time window analysis (last N seconds)
- Source IP tracking
- Port sequence detection
- Timing pattern analysis

### 3. DDoS Detector (`detectors/ddos_detector.py`)

**Detection Algorithm**:
```python
# Identify DDoS by:
# 1. Packet rate spike detection
# 2. Source IP diversity (botnet signature)
# 3. Single target focus
# 4. Sustained duration

Thresholds:
- pps > 3x baseline: MEDIUM
- pps > 10x baseline + diverse sources: HIGH
- pps > 50x baseline: CRITICAL
```

**Statistical Methods**:
- Moving average for baseline
- Standard deviation for spike detection
- Source entropy calculation
- Target concentration ratio

### 4. Data Exfiltration Detector (`detectors/exfiltration_detector.py`)

**Detection Algorithm**:
```python
# Identify exfiltration by:
# 1. Large outbound transfers
# 2. Unusual destinations
# 3. Off-hours activity
# 4. Encrypted protocol usage

Thresholds:
- outbound > 100MB to single destination: MEDIUM
- outbound > 1GB: HIGH
- suspicious destination + large transfer: CRITICAL
```

**Context Factors**:
- Time of day (off-hours suspicious)
- Destination reputation
- Historical transfer patterns
- Protocol analysis (HTTPS to hide)

### 5. Brute Force Detector (`detectors/brute_force_detector.py`)

**Detection Algorithm**:
```python
# Identify brute force by:
# 1. Repeated connection attempts
# 2. Same source, same destination port
# 3. Authentication service targeted (SSH, RDP, etc.)
# 4. Failed attempt indicators

Thresholds:
- attempts > 10: LOW
- attempts > 50: MEDIUM
- attempts > 100: HIGH
- attempts > 500: CRITICAL
```

**Service-Specific Logic**:
- SSH: Port 22, multiple handshakes
- RDP: Port 3389, connection failures
- HTTP: Multiple 401/403 responses
- FTP: Multiple login attempts

### 6. AI Threat Analyzer (`ai/ai_analyzer.py`)

**Core Functionality**:
```python
class AIThreatAnalyzer:
    """
    Uses Claude AI to analyze suspicious patterns
    """
    
    async def analyze_threat(self, 
                            alert: Alert,
                            packet_context: List[Packet],
                            flow_context: List[Flow]) -> AIAnalysis:
        """
        Send suspicious traffic to Claude for analysis
        Returns enhanced alert with insights
        """
        
    async def explain_pattern(self, 
                             pattern: dict) -> str:
        """
        Get natural language explanation of pattern
        """
        
    def calculate_confidence(self,
                            ai_response: dict) -> float:
        """
        Extract confidence score from AI analysis
        """
```

**AI Analysis Includes**:
- Threat classification
- Confidence score (0-100)
- Natural language explanation
- Evidence points
- Predicted next steps
- Recommended actions

### 7. Prompt Templates (`ai/prompt_templates.py`)

**Template Categories**:

#### Port Scan Analysis Prompt
```python
PORT_SCAN_PROMPT = """
Analyze this port scanning activity:

Source IP: {source_ip}
Target IP: {target_ip}
Ports scanned: {port_count}
Port range: {min_port}-{max_port}
Duration: {duration} seconds
Pattern: {sequential/random}

Traffic sample:
{packet_summary}

Assess:
1. Threat level (LOW/MEDIUM/HIGH/CRITICAL)
2. Likely attacker intent
3. Sophistication level
4. Predicted next steps
5. Recommended defensive actions

Respond in JSON format:
{
  "threat_level": "...",
  "confidence": 0-100,
  "explanation": "...",
  "evidence": [...],
  "predictions": [...],
  "recommendations": [...]
}
"""
```

#### DDoS Analysis Prompt
```python
DDOS_PROMPT = """
Analyze this traffic flood:

Target: {target_ip}:{target_port}
Packet rate: {packets_per_second} pps
Unique sources: {source_count}
Duration: {duration} seconds
Baseline normal: {baseline_pps} pps

Attack characteristics:
- Source diversity: {source_diversity}
- Protocol: {protocol}
- Packet flags: {flags}

Assess:
1. Attack type (SYN flood, UDP flood, HTTP flood, etc.)
2. Severity and business impact
3. Botnet indicators
4. Mitigation strategies

Respond in JSON...
"""
```

#### Exfiltration Analysis Prompt
#### Brute Force Analysis Prompt

### 8. Detection Engine (`detection_engine.py`)

**Main Orchestrator**:
```python
class DetectionEngine:
    """
    Coordinates all detectors and AI analysis
    """
    
    def __init__(self, enable_ai=True):
        self.detectors = [
            PortScanDetector(),
            DDoSDetector(),
            ExfiltrationDetector(),
            BruteForceDetector()
        ]
        self.ai_analyzer = AIThreatAnalyzer() if enable_ai else None
        self.baseline_profile = None
        
    async def process_traffic(self, 
                             packets: List[Packet]) -> List[Alert]:
        """
        Main detection pipeline:
        1. Aggregate packets into flows
        2. Run traditional detectors
        3. Filter to high-confidence alerts
        4. Send suspicious patterns to AI
        5. Enhance alerts with AI insights
        6. Return final alert list
        """
        
        # Step 1: Flow aggregation
        flows = self._aggregate_flows(packets)
        
        # Step 2: Traditional detection
        alerts = []
        for detector in self.detectors:
            alerts.extend(detector.analyze(packets, flows))
        
        # Step 3: AI enhancement (if enabled)
        if self.ai_analyzer and alerts:
            enhanced_alerts = await self._enhance_with_ai(alerts, packets)
            return enhanced_alerts
        
        return alerts
```

**Pipeline Benefits**:
- Fast traditional detectors catch obvious threats
- AI provides context for ambiguous cases
- Configurable (can disable AI for offline mode)
- Extensible (easy to add detectors)

### 9. AI Configuration (`ai/ai_config.py`)

```python
class AIConfig:
    """
    Configuration for AI integration
    """
    
    # API settings
    API_KEY = os.getenv('ANTHROPIC_API_KEY')
    MODEL = "claude-sonnet-4-20250514"
    MAX_TOKENS = 1000
    
    # When to trigger AI analysis
    AI_TRIGGER_THRESHOLDS = {
        'min_severity': 'MEDIUM',  # Only MEDIUM+ alerts
        'min_confidence': 0.6,      # Traditional detector confidence
        'max_alerts_per_minute': 10 # Rate limiting
    }
    
    # Cost controls
    ENABLE_AI = True
    MAX_API_CALLS_PER_HOUR = 100
    CACHE_SIMILAR_PATTERNS = True
```

## Testing Strategy

### Unit Tests (`tests/test_detectors.py`)

Test each detector in isolation:

```python
def test_port_scan_detector():
    """Test port scan detection accuracy"""
    sim = TrafficSimulator()
    detector = PortScanDetector()
    
    # Test 1: Should detect obvious port scan
    scan_packets = sim.generate_port_scan(port_count=100)
    alerts = detector.analyze(scan_packets, [])
    assert len(alerts) == 1
    assert alerts[0].alert_type == AlertType.PORT_SCAN
    assert alerts[0].severity == AlertSeverity.HIGH
    
    # Test 2: Should NOT false positive on normal traffic
    normal_packets = sim.generate_normal_traffic(count=100)
    alerts = detector.analyze(normal_packets, [])
    assert len(alerts) == 0
    
    # Test 3: Should detect slow scan
    slow_scan = sim.generate_port_scan(port_count=20)
    # Add delays between packets
    # Should still detect
```

### Integration Tests (`tests/test_detection_engine.py`)

Test complete pipeline:

```python
async def test_full_detection_pipeline():
    """Test traditional + AI detection"""
    engine = DetectionEngine(enable_ai=True)
    sim = TrafficSimulator()
    
    # Generate mixed traffic
    packets = sim.generate_mixed_scenario()
    
    # Run detection
    alerts = await engine.process_traffic(packets)
    
    # Verify results
    assert len(alerts) >= 2  # Should catch port scan + brute force
    
    # Check AI enhancements
    for alert in alerts:
        assert hasattr(alert, 'ai_explanation')
        assert alert.confidence > 0
        assert len(alert.recommendations) > 0
```

### AI Quality Tests (`tests/test_ai_integration.py`)

Verify AI responses:

```python
async def test_ai_port_scan_analysis():
    """Verify AI provides useful analysis"""
    analyzer = AIThreatAnalyzer()
    
    # Create test alert
    alert = Alert(
        alert_type=AlertType.PORT_SCAN,
        severity=AlertSeverity.MEDIUM,
        source_ip="45.142.212.61",
        # ... other fields
    )
    
    # Get AI analysis
    analysis = await analyzer.analyze_threat(alert, packets, flows)
    
    # Verify response quality
    assert analysis.confidence >= 50
    assert len(analysis.explanation) > 50  # Substantive explanation
    assert len(analysis.recommendations) >= 2
    assert analysis.threat_level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
```

## Performance Targets

### Traditional Detectors
- Process 10,000 packets/second minimum
- < 100ms latency for detection
- < 1% false positive rate
- > 95% true positive rate

### AI Integration
- < 2 seconds for AI analysis
- Cache similar patterns (save API calls)
- Rate limit to prevent cost explosion
- Graceful degradation if API unavailable

## Deliverables

Files to create:
```
detectors/
├── __init__.py
├── base_detector.py          (~100 lines)
├── port_scan_detector.py     (~150 lines)
├── ddos_detector.py          (~150 lines)
├── exfiltration_detector.py  (~150 lines)
└── brute_force_detector.py   (~150 lines)

ai/
├── __init__.py
├── ai_analyzer.py            (~200 lines)
├── prompt_templates.py       (~150 lines)
└── ai_config.py              (~50 lines)

detection_engine.py           (~200 lines)

tests/
├── test_detectors.py         (~300 lines)
├── test_ai_integration.py    (~200 lines)
└── test_detection_engine.py  (~200 lines)
```

**Total**: ~1,800 lines of code + tests

## Dependencies to Add

```txt
# requirements.txt additions
anthropic>=0.20.0          # Claude API client
python-dotenv>=1.0.0       # Environment variables
aiohttp>=3.9.0             # Async HTTP for AI calls
numpy>=1.24.0              # Statistical analysis
scipy>=1.11.0              # Advanced statistics
```

## Success Criteria

- [ ] All detectors achieve > 90% accuracy on test data
- [ ] AI integration provides meaningful insights
- [ ] Detection latency < 100ms for traditional, < 2s with AI
- [ ] False positive rate < 5%
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Documentation complete

## Risk Mitigation

**Risk**: AI API costs too high
**Mitigation**: 
- Only analyze MEDIUM+ alerts
- Cache similar patterns
- Rate limit API calls
- Provide offline mode

**Risk**: AI analysis too slow
**Mitigation**:
- Traditional detectors run first (fast)
- AI runs async (non-blocking)
- Display traditional alerts immediately
- Enhance with AI when available

**Risk**: Poor AI response quality
**Mitigation**:
- Well-crafted prompts with examples
- Response validation
- Fallback to traditional alerts
- Human review of prompts

## Next Steps After Session 2

With detection engine complete, Session 3 will build:
- Flask backend API
- WebSocket server for real-time updates
- Database for storing alerts/traffic
- REST endpoints for frontend

This prepares for Session 4 (Dashboard) where everything comes together visually.

---

**Status**: Ready to start when on PC with Claude Code
**Prerequisites**: 
- [ ] Claude API key obtained
- [ ] Project in Git
- [ ] Virtual environment set up
- [ ] Dependencies installed
