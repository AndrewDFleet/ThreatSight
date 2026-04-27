# Architecture Documentation

## System Overview

Network Threat Visualizer is a three-tier application combining network traffic analysis, AI-powered threat detection, and real-time visualization.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Dashboard  │  │  Alert Panel │  │ Report View  │       │
│  │  (Charts)   │  │  (Real-time) │  │  (AI-gen)    │       │
│  └─────────────┘  └──────────────┘  └──────────────┘       │
│         HTML5 + CSS3 + JavaScript + Chart.js                │
└─────────────────────────────────────────────────────────────┘
                          ↕ WebSocket / REST
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          Detection Engine (Core Logic)               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │   │
│  │  │  Port Scan  │  │    DDoS     │  │ Brute Force│  │   │
│  │  │  Detector   │  │  Detector   │  │  Detector  │  │   │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │   │
│  │  ┌──────────────────────────────────────────────┐  │   │
│  │  │      AI Threat Analyzer (Claude API)         │  │   │
│  │  └──────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Flask API   │  │  WebSocket   │  │  AI Report   │     │
│  │  (REST)      │  │  Handler     │  │  Generator   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                     Python 3.8+ / Flask                      │
└─────────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────────┐
│                      Data Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Traffic    │  │   SQLite     │  │   Claude     │     │
│  │  Simulator   │  │  (Alerts,    │  │     API      │     │
│  │  (or Scapy)  │  │   Traffic)   │  │ (External)   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Data Layer

#### Traffic Source (Dual Mode)
**Demo Mode**: `TrafficSimulator`
- Generates realistic network patterns
- Injects controllable attack scenarios
- Reproducible for testing
- No special privileges required

**Production Mode**: `Scapy/libpcap`
- Captures real network traffic
- Requires root/CAP_NET_RAW
- Actual threat detection
- Production deployment

#### Data Storage: SQLite
**Tables**:
- `packets`: Raw packet data (limited retention)
- `flows`: Aggregated flow records
- `alerts`: Security events
- `baselines`: Normal traffic profiles
- `reports`: Generated AI reports

**Retention Policy**:
- Packets: 24 hours
- Flows: 7 days
- Alerts: 90 days
- Reports: Indefinite

#### External APIs
**Claude API (Anthropic)**
- AI threat analysis
- Report generation
- Natural language explanations
- Confidence scoring

### 2. Application Layer

#### Detection Engine
**Traditional Detectors** (Rule-based):
```python
Packet Stream → Flow Aggregation → Detector Suite → Alerts
                                    ↓
                            [Port Scan Detector]
                            [DDoS Detector]
                            [Exfiltration Detector]
                            [Brute Force Detector]
```

**Detection Pipeline**:
1. Receive packet batch
2. Aggregate into flows
3. Run all detectors in parallel
4. Filter by confidence threshold
5. Deduplicate alerts
6. Send to AI for enhancement (optional)
7. Emit final alerts

**AI Enhancement Layer**:
```python
Medium/High Alerts → AI Analyzer → Enhanced Alerts
                     ↓
              [Claude API]
                     ↓
          Explanation + Confidence
          Evidence + Predictions
          Recommendations
```

#### Flask Backend
**REST API Endpoints**:
```
GET  /api/stats              - Current network statistics
GET  /api/alerts             - Recent alerts (paginated)
GET  /api/alerts/:id         - Alert details
POST /api/alerts/:id/ack     - Acknowledge alert
GET  /api/flows              - Active flows
POST /api/simulate/:scenario - Trigger attack simulation
GET  /api/reports            - List generated reports
POST /api/reports/generate   - Generate new report
```

**WebSocket Events**:
```
→ connect                    - Client connects
← stats_update               - Real-time statistics
← new_alert                  - Alert notification
← flow_update                - Flow state changes
→ request_analysis           - Request AI analysis
← analysis_result            - AI analysis complete
```

#### AI Components

**AI Analyzer** (`ai/ai_analyzer.py`):
- Receives suspicious patterns
- Constructs analysis prompts
- Calls Claude API
- Parses and validates responses
- Caches similar patterns

**Report Generator** (`ai/report_generator.py`):
- Incident reports (single event)
- Daily summaries (multiple events)
- Trend analysis (historical)
- Executive summaries

**Prompt Templates** (`ai/prompt_templates.py`):
- Pre-defined analysis prompts
- Structured output requirements
- Example-based learning
- JSON response format

### 3. Presentation Layer

#### Dashboard Components

**Real-time Traffic Graph**:
- Line chart: Packets/sec over time
- Stacked area: Protocol distribution
- Updates every 1 second via WebSocket

**Alert Feed**:
- Live scrolling list
- Color-coded by severity
- Click for AI explanation
- Acknowledge/dismiss actions

**Network Map**:
- Geographic visualization
- Attack source locations
- Target highlighting
- Flow animations

**Statistics Panel**:
- Total packets/bytes
- Active flows count
- Protocol breakdown
- Top talkers list

**Control Panel**:
- Start/stop monitoring
- Inject attack scenarios
- Generate reports
- Export data

## Data Flow

### Normal Traffic Processing

```
1. Packet Capture/Generation
   ↓
2. Packet → TrafficProcessor
   ↓
3. Flow Aggregation
   ↓
4. Statistics Update
   ↓
5. WebSocket → Dashboard
   (Live visualization)
```

### Attack Detection Flow

```
1. Packet Batch (100-1000 packets)
   ↓
2. Flow Aggregation
   ↓
3. Detector Suite Analysis
   ├→ Port Scan Detector
   ├→ DDoS Detector
   ├→ Exfiltration Detector
   └→ Brute Force Detector
   ↓
4. Alert Generation
   ↓
5. Confidence Filtering
   ↓
6. [If Medium/High] → AI Analyzer
   ↓
7. AI Enhancement
   - Natural language explanation
   - Evidence extraction
   - Prediction generation
   - Recommendation creation
   ↓
8. Enhanced Alert → Database
   ↓
9. WebSocket Broadcast
   ↓
10. Dashboard Display
    - Visual notification
    - Sound alert (optional)
    - Detailed view on click
```

### Report Generation Flow

```
1. User requests report
   ↓
2. Gather relevant data
   - Alerts in time window
   - Traffic statistics
   - Flow patterns
   ↓
3. AI Report Generator
   ↓
4. Claude API Call
   - Incident summary
   - Technical details
   - Recommendations
   ↓
5. Format Output
   - Markdown
   - PDF (optional)
   ↓
6. Save to Database
   ↓
7. Download Link → User
```

## Scaling Considerations

### Current Design (Demo/Small Network)
- Single Python process
- SQLite database
- Local file storage
- Handles ~10,000 packets/sec

### Production Scaling Path

**Horizontal Scaling**:
- Multiple detector workers
- Redis for packet queue
- PostgreSQL for storage
- Load-balanced Flask instances

**Performance Optimizations**:
- Packet sampling (1 in N)
- Flow-level analysis only
- Batch processing
- Async I/O throughout

**Cost Optimization**:
- AI call rate limiting
- Pattern caching
- Similarity detection
- Configurable AI triggers

## Security Considerations

### Application Security
- API authentication (JWT tokens)
- Rate limiting on endpoints
- Input validation
- SQL injection prevention
- XSS protection

### Network Security
- Packet capture privileges (minimal)
- Encrypted WebSocket (WSS)
- HTTPS for REST API
- API key protection (.env)

### Data Privacy
- No PII in captured packets
- Payload truncation
- Retention policies
- GDPR compliance ready

## Technology Decisions

### Why Flask?
- Lightweight and fast
- Excellent WebSocket support (Flask-SocketIO)
- Easy to deploy
- Good for real-time applications

### Why SQLite?
- No separate database server
- Perfect for demo/single instance
- Easy migration to PostgreSQL
- Built-in Python support

### Why Client-Side Rendering?
- Real-time updates easier
- Lower server load
- Better user experience
- Chart.js performance

### Why Claude AI?
- State-of-art reasoning
- Excellent context understanding
- Natural language generation
- Reliable API

## Future Architecture Evolution

### Phase 1: Current (Demo)
- Single instance
- Simulated traffic
- Basic detection
- AI enhancement

### Phase 2: Small Deployment
- Real packet capture
- Multiple detectors
- Advanced AI features
- Report generation

### Phase 3: Production
- Distributed architecture
- Machine learning models
- Threat intelligence feeds
- Enterprise features

## Deployment Modes

### Development
```bash
python app.py
# Runs on localhost:5000
# Debug mode enabled
# Simulated traffic only
```

### Demo
```bash
python app.py --demo
# Pre-loaded scenarios
# Automated attack injection
# Presentation mode
```

### Production
```bash
gunicorn -w 4 -k gevent app:app
# Multiple workers
# Real packet capture
# Production database
# HTTPS enabled
```

---

**See Also**:
- [API Documentation](api.md)
- [Detection Algorithms](detection-algorithms.md)
- [Deployment Guide](deployment.md)
