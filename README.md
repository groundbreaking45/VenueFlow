# 🚀 VenueFlow — Real-Time Venue Intelligence Platform

> AI-powered crowd optimization for large-scale venues (70,000+ capacity)  
> Turning chaos into flow, in real time. Predictive. Not reactive.

---

## 🧠 The Problem

Managing **70,000+ fans** in a live stadium is a logistical and safety nightmare:

- **28-minute gate queues** at peak entry — fans miss kick-off
- **Poor crowd distribution** → dangerous density hotspots → safety incidents
- **Delayed incident response** — reactive systems notify staff *after* problems escalate
- **Lost F&B revenue** due to congestion blocking access to concession stands
- **Zero real-time data** for venue managers — decisions made on guesswork, not intelligence

Traditional systems are **reactive**. VenueFlow is **predictive**.

---

## ⚡ The Solution

VenueFlow is a real-time, AI-driven platform that:

- **Monitors** crowd density across all venue zones (live heatmap + Google Maps overlay)
- **Predicts** bottlenecks before they happen using density trend analysis
- **Automatically dispatches** staff to zones exceeding safety thresholds
- **Dynamically redistributes** crowds using personalised incentives (discounts, offers)
- **Syncs attendee devices** via Firebase Realtime Database for live navigation & alerts
- **Enables instant SOS** with precise seat pinpoint to emergency responders

---

## 🖥️ Features

### 🎛️ Manager Dashboard
| Feature | Description |
|---------|-------------|
| Live KPIs | Occupancy, bottlenecks, F&B revenue, fan satisfaction |
| Interactive Heatmap | Canvas-rendered crowd density with real-time animation |
| Google Maps Panel | Crowd heatmap overlay on live Google Maps with traffic layer |
| AI Command Center | Event log with predictive alerts and automated decisions |
| Staff Dispatch Board | One-click deployment with status tracking |
| Incident Feed | Real-time log with severity classification and filtering |
| Queue Analytics | Chart.js bar chart with 30s rolling averages |
| Incentive Engine | Dynamic offers triggered by zone density thresholds |
| CSV Export | Full zone + incident report downloadable anytime |

### 📱 Attendee View
| Feature | Description |
|---------|-------------|
| Smart Navigation | Indoor crowd-aware routing with real-time wait times |
| Push Notifications | Geo-fenced alerts for congestion and offers |
| Food Pre-Order | Skip half-time queues with seat delivery |
| SOS Button | Hold-to-confirm with emergency type selection and seat pinpoint |
| Live Offers | Personalised incentives based on nearby zone density |
| Feedback / NPS | In-app satisfaction polling feeding AI engine |

---

## 🧩 Core Highlights

| Capability | Implementation |
|------------|----------------|
| Predictive AI | Zone density trend + threshold-based dispatch rules |
| Real-time heatmap | Canvas API with radial gradient overlays |
| Google Maps | Visualization API crowd heatmap + traffic layer |
| Firebase sync | Realtime Database zone snapshot every 5s |
| Security | CSP headers, XSS sanitisation, SOS rate limiter |
| Accessibility | ARIA roles, live regions, keyboard navigation |
| Testing | 67 unit tests across 11 suites (100% pass rate) |
| Analytics | CSV export with zone density and incident history |

---

## 🧪 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript (ES6+) |
| Charts | Chart.js 4.4 |
| Maps | Google Maps JavaScript API + Visualization Library |
| Real-time Sync | Firebase Realtime Database |
| Canvas Rendering | Canvas 2D API |
| Text Layout | Pretext.js (with canvas fallback) |
| Testing | Custom in-browser + Node.js test harness (67 tests) |

---

## 🏗️ Structure

```
VenueFlow/
├── index.html          # Main application shell + Google Maps / Firebase setup
├── style.css           # Complete design system (light + dark theme)
├── app.js              # Application logic + Google Maps + Firebase integration
├── venueflow.test.js   # 67 unit tests (security, logic, maps, Firebase)
└── test-runner.html    # Visual in-browser test report
```

---

## ⌨️ Shortcuts

| Key | Action |
|-----|--------|
| `M` | Manager View |
| `A` | Attendee View |
| `T` | Toggle Dark / Light Theme |
| `E` | Export CSV Report |
| `?` | Show Keyboard Shortcuts |
| `Esc` | Close Modal |

---

## 🔒 Security

- **Content Security Policy** — allowlists Google Maps, Firebase, CDN domains
- **XSS Sanitisation** — all user-facing strings escaped via `DOM.sanitise()`
- **SOS Rate Limiting** — max 2 alerts per 30 seconds to prevent abuse
- **No eval() / innerHTML with user data** — structured DOM construction throughout
- **Referrer Policy** — `no-referrer` on all requests

---

## 🧪 Testing

Run in Node.js:
```bash
node venueflow.test.js
```

Or open `test-runner.html` in any browser for the visual report.

**Coverage:**
- XSS attack vector sanitisation (7 vectors)
- SOS rate limiter logic
- Zone density classification and filtering
- Density simulation bounds
- CSV export formatting
- KPI analytics calculations
- Google Maps geocoordinate math
- Firebase snapshot integrity
- Incentive trigger thresholds
- Incident filter logic
- Problem statement alignment validation

---

## 🏁 TL;DR

VenueFlow doesn't just monitor crowds — it **orchestrates** them.

> **Problem:** 70,000 fans. 28-min queues. Zero real-time intelligence.  
> **Solution:** Predictive AI + Google Maps + Firebase = crowds that flow, not jam.
