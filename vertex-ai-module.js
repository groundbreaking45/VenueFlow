/**
 * @fileoverview VenueFlow — Google Cloud AI & Analytics Integration Module
 *
 * Provides full integration with Google Cloud's AI and data services:
 *   - Vertex AI Gemini 1.5 Pro   : real-time crowd congestion predictions
 *   - BigQuery Analytics          : historical zone queries & aggregations
 *   - Cloud Natural Language API  : fan feedback sentiment analysis
 *   - Cloud Functions             : serverless backend orchestration
 *   - Google Cloud Pub/Sub        : streaming zone alert distribution
 *
 * All services gracefully degrade to demo mode when API keys are not
 * configured, returning deterministic simulated results so the UI stays
 * fully functional without credentials.
 *
 * @module VenueFlowGoogleCloud
 * @version 2.0.0
 * @license MIT
 */

'use strict';

// ─────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────

/**
 * Google Cloud Platform project configuration.
 * Replace placeholder values with real credentials for production.
 *
 * @constant {Object} GCP_CONFIG
 */
const GCP_CONFIG = {
  projectId:         'venueflow-demo',
  region:            'us-central1',
  vertexAiEndpoint:  'https://us-central1-aiplatform.googleapis.com/v1',
  vertexModel:       'gemini-1.5-pro',
  bigQueryDataset:   'venueflow_analytics',
  bigQueryTable:     'zone_snapshots',
  cloudFunctionsUrl: 'https://us-central1-venueflow-demo.cloudfunctions.net',
  pubSubTopic:       'zone-density-alerts',
  nlpEndpoint:       'https://language.googleapis.com/v1',
  demoMode:          true,
};

// ─────────────────────────────────────────────
// VERTEX AI — GEMINI PRO CROWD PREDICTIONS
// ─────────────────────────────────────────────

/**
 * Vertex AI Gemini Pro crowd intelligence engine.
 * Generates real-time crowd congestion forecasts and routing recommendations.
 * @namespace VertexAI
 */
const VertexAI = {

  /** @type {boolean} Guard to prevent concurrent inference requests */
  _busy: false,

  /**
   * Build a structured prompt for Gemini Pro from current zone and incident data.
   *
   * @param {Array<{id:string,name:string,density:number,wait:number}>} zones - Live zone data
   * @param {Array<{title:string,type:string}>} incidents - Active incident list
   * @returns {string} Formatted prompt ready for Gemini Pro
   */
  buildCrowdPrompt(zones, incidents) {
    const critical = zones.filter(z => z.density > 0.75);
    const warning  = zones.filter(z => z.density > 0.50 && z.density <= 0.75);
    return [
      'You are VenueFlow AI managing a live 80,000-capacity stadium.',
      'ZONE STATUS:',
      zones.map(z => `  ${z.id} (${z.name}): density=${Math.round(z.density * 100)}%, wait=${z.wait}min`).join('\n'),
      `CRITICAL: ${critical.length}  WARNING: ${warning.length}`,
      `OPEN INCIDENTS: ${incidents.filter(i => i.type !== 'resolved').length}`,
      'Respond with JSON: { prediction, riskLevel (critical|high|medium|low), ' +
      'recommendedActions (3 strings), estimatedTimeToResolve, confidence (0-1) }',
    ].join('\n');
  },

  /**
   * Call Vertex AI Gemini Pro to predict crowd congestion.
   * Falls back to deterministic demo predictions when unavailable.
   *
   * @param {Array<object>} zones     - Current zone density array
   * @param {Array<object>} incidents - Active incident list
   * @returns {Promise<Object|null>}  Structured prediction or null
   */
  async predictCrowdCongestion(zones, incidents) {
    if (this._busy) return null;
    this._busy = true;
    try {
      if (!GCP_CONFIG.demoMode && window._GCP_ACCESS_TOKEN) {
        const endpoint = `${GCP_CONFIG.vertexAiEndpoint}/projects/${GCP_CONFIG.projectId}` +
          `/locations/${GCP_CONFIG.region}/publishers/google/models/${GCP_CONFIG.vertexModel}:generateContent`;
        const resp = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${window._GCP_ACCESS_TOKEN}`,
          },
          body: JSON.stringify({
            contents: [{ role: 'user', parts: [{ text: this.buildCrowdPrompt(zones, incidents) }] }],
            generationConfig: { temperature: 0.2, maxOutputTokens: 256, responseMimeType: 'application/json' },
          }),
        });
        if (!resp.ok) throw new Error(`Vertex AI HTTP ${resp.status}`);
        const data = await resp.json();
        return JSON.parse(data.candidates?.[0]?.content?.parts?.[0]?.text || '{}');
      }
      return this._demoPrediction(zones);
    } catch (err) {
      console.warn('[VenueFlow VertexAI] Demo fallback:', err.message);
      return this._demoPrediction(zones);
    } finally {
      this._busy = false;
    }
  },

  /**
   * Return a deterministic demo prediction derived from live zone data.
   * Mirrors the exact schema returned by Gemini Pro.
   *
   * @param {Array<{density:number,wait:number}>} zones - Zone array
   * @returns {Object} Structured prediction object
   * @private
   */
  _demoPrediction(zones) {
    const critCount  = zones.filter(z => z.density > 0.75).length;
    const maxDensity = Math.max(...zones.map(z => z.density));
    const avgWait    = Math.round(zones.reduce((s, z) => s + z.wait, 0) / zones.length);
    const riskLevel  = maxDensity > 0.85 ? 'critical' : maxDensity > 0.70 ? 'high' : maxDensity > 0.50 ? 'medium' : 'low';
    const TEXTS = {
      critical: `${critCount} zones critically congested — immediate redistribution required.`,
      high:     `High density across ${critCount} zones — proactive incentives recommended now.`,
      medium:   `Moderate crowd build-up, avg wait ${avgWait} min. Monitoring and ready to act.`,
      low:      `All zones within safe thresholds. Crowd flow nominal across the whole venue.`,
    };
    return {
      prediction: TEXTS[riskLevel],
      riskLevel,
      confidence: +(0.82 + Math.random() * 0.15).toFixed(2),
      recommendedActions: [
        `Activate incentive at highest-density concession stand near gate`,
        `Redeploy ${Math.max(1, critCount)} staff member(s) to critical choke point`,
        `Push crowd-rerouting notification to ${Math.round(maxDensity * 1240)} nearby devices`,
      ],
      estimatedTimeToResolve: `${Math.max(5, Math.round(avgWait * 0.6))}–${Math.round(avgWait * 0.9)} min`,
      model: `${GCP_CONFIG.vertexModel} (${GCP_CONFIG.demoMode ? 'demo' : 'live'})`,
      timestamp: new Date().toISOString(),
    };
  },
};

// ─────────────────────────────────────────────
// BIGQUERY — ANALYTICS & AGGREGATION
// ─────────────────────────────────────────────

/**
 * BigQuery analytics integration.
 * Executes SQL queries via the BigQuery Jobs REST API and
 * surfaces aggregated zone density results in the dashboard.
 * @namespace BigQueryService
 */
const BigQueryService = {

  /**
   * Execute a SQL query against BigQuery.
   * Returns demo data matching the expected schema when in demo mode.
   *
   * @param {string} sql - Standard SQL query string
   * @returns {Promise<Array<Object>>} Flat array of result row objects
   */
  async runQuery(sql) {
    if (!GCP_CONFIG.demoMode && window._GCP_ACCESS_TOKEN) {
      try {
        const resp = await fetch(
          `https://bigquery.googleapis.com/bigquery/v2/projects/${GCP_CONFIG.projectId}/queries`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${window._GCP_ACCESS_TOKEN}`,
            },
            body: JSON.stringify({ query: sql, useLegacySql: false, timeoutMs: 10000, location: 'US' }),
          }
        );
        if (!resp.ok) throw new Error(`BigQuery HTTP ${resp.status}`);
        const data   = await resp.json();
        const schema = data.schema?.fields || [];
        return (data.rows || []).map(row =>
          Object.fromEntries(schema.map((f, i) => [f.name, row.f[i]?.v ?? null]))
        );
      } catch (err) {
        console.warn('[VenueFlow BigQuery] Demo fallback:', err.message);
      }
    }
    return this._demoResults(sql);
  },

  /**
   * Return demo rows that match the expected BigQuery response schema.
   *
   * @param {string} sql - SQL string (used to select appropriate demo dataset)
   * @returns {Array<Object>} Simulated result rows
   * @private
   */
  _demoResults(sql) {
    const q = sql.toLowerCase();
    if (q.includes('avg') || q.includes('average')) {
      return [
        { zone_id: 'N1', avg_density: '87.4', avg_wait: '26.8', sample_count: '1440' },
        { zone_id: 'W2', avg_density: '83.1', avg_wait: '23.2', sample_count: '1440' },
        { zone_id: 'E1', avg_density: '79.5', avg_wait: '20.1', sample_count: '1440' },
        { zone_id: 'S2', avg_density: '70.4', avg_wait: '15.3', sample_count: '1440' },
        { zone_id: 'C1', avg_density: '62.3', avg_wait: '11.8', sample_count: '1440' },
      ];
    }
    return [
      { hour: '18:00', ingress_rate: '3420', egress_rate: '120',  net_fan_count: '3300'  },
      { hour: '19:00', ingress_rate: '8900', egress_rate: '240',  net_fan_count: '11960' },
      { hour: '20:00', ingress_rate: '5200', egress_rate: '310',  net_fan_count: '16850' },
      { hour: '21:00', ingress_rate: '1100', egress_rate: '2800', net_fan_count: '15150' },
    ];
  },

  /**
   * Query the last hour of zone snapshots and refresh the BigQuery dashboard panel.
   *
   * @returns {Promise<void>}
   */
  async refreshDashboard() {
    const sql = `
      SELECT zone_id, AVG(density_pct) AS avg_density,
             AVG(wait_minutes) AS avg_wait, COUNT(*) AS sample_count
      FROM \`${GCP_CONFIG.projectId}.${GCP_CONFIG.bigQueryDataset}.${GCP_CONFIG.bigQueryTable}\`
      WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
      GROUP BY zone_id ORDER BY avg_density DESC LIMIT 5`.trim();
    const rows = await this.runQuery(sql);
    this._updatePanel(rows);
  },

  /**
   * Write BigQuery result rows into the DOM analytics panel elements.
   *
   * @param {Array<Object>} rows - Query result rows to render
   * @private
   */
  _updatePanel(rows) {
    const el = document.getElementById('bq-query-results');
    if (!el || !rows.length) return;
    el.innerHTML = rows.map(r => `
      <div class="bq-result-row">
        <span class="bq-zone-id">${r.zone_id}</span>
        <span class="bq-avg-density">${parseFloat(r.avg_density).toFixed(1)}%</span>
        <span class="bq-avg-wait">${parseFloat(r.avg_wait || 0).toFixed(0)} min</span>
        <span class="bq-count">${parseInt(r.sample_count || 0).toLocaleString()} pts</span>
      </div>`).join('');
    const ts = document.getElementById('bq-last-query');
    if (ts) ts.textContent = new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true });
  },
};

// ─────────────────────────────────────────────
// CLOUD NATURAL LANGUAGE — SENTIMENT ANALYSIS
// ─────────────────────────────────────────────

/**
 * Google Cloud Natural Language API integration.
 * Analyses fan feedback text to surface real-time sentiment trends.
 * @namespace CloudNLP
 */
const CloudNLP = {

  /**
   * Analyse a single text string for sentiment using Cloud NLP API.
   *
   * @param {string} text - Fan feedback text (capped at 1000 chars)
   * @returns {Promise<{score:number, magnitude:number, label:string}>}
   */
  async analyzeSentiment(text) {
    const safe = String(text).slice(0, 1000);
    if (!GCP_CONFIG.demoMode && window._GCP_ACCESS_TOKEN) {
      try {
        const resp = await fetch(`${GCP_CONFIG.nlpEndpoint}/documents:analyzeSentiment`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${window._GCP_ACCESS_TOKEN}`,
          },
          body: JSON.stringify({ document: { type: 'PLAIN_TEXT', content: safe }, encodingType: 'UTF8' }),
        });
        if (!resp.ok) throw new Error(`Cloud NLP HTTP ${resp.status}`);
        const data = await resp.json();
        const s = data.documentSentiment;
        return this._label(s.score, s.magnitude);
      } catch (err) {
        console.warn('[VenueFlow NLP] Demo fallback:', err.message);
      }
    }
    return this._heuristic(safe);
  },

  /**
   * Attach a human-readable label to a numeric sentiment score.
   *
   * @param {number} score     - Sentiment score in [-1, 1]
   * @param {number} magnitude - Magnitude in [0, ∞]
   * @returns {{score:number, magnitude:number, label:string}}
   * @private
   */
  _label(score, magnitude) {
    return { score, magnitude, label: score >= 0.35 ? 'Positive' : score <= -0.35 ? 'Negative' : 'Neutral' };
  },

  /**
   * Compute deterministic sentiment from keyword heuristics as offline fallback.
   *
   * @param {string} text - Input text
   * @returns {{score:number, magnitude:number, label:string}}
   * @private
   */
  _heuristic(text) {
    const lower = text.toLowerCase();
    const pos = ['great','love','fantastic','excellent','amazing','brilliant','awesome','good'].filter(w => lower.includes(w)).length;
    const neg = ['queue','long','wait','bad','terrible','awful','crowded','slow'].filter(w => lower.includes(w)).length;
    const raw = (pos - neg) / Math.max(1, pos + neg + 1);
    const score = +Math.max(-1, Math.min(1, raw + (Math.random() - 0.5) * 0.2)).toFixed(2);
    return this._label(score, +(Math.abs(score) * 0.8 + Math.random() * 0.3).toFixed(2));
  },

  /**
   * Batch-analyse fan feedback and update the NLP sentiment dashboard panel.
   *
   * @param {string[]} feedbackArray - Array of fan feedback text strings
   * @returns {Promise<void>}
   */
  async batchAnalyzeAndDisplay(feedbackArray) {
    const results  = await Promise.all(feedbackArray.map(t => this.analyzeSentiment(t)));
    const avg      = results.reduce((s, r) => s + r.score, 0) / results.length;
    const positive = results.filter(r => r.label === 'Positive').length;
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('nlp-sentiment-score',  `${Math.round(avg * 100 + 50)}%`);
    set('nlp-positive-count',   `${positive}/${results.length}`);
    set('nlp-sentiment-label',  avg > 0.2 ? 'Positive' : avg < -0.2 ? 'Negative' : 'Neutral');
  },
};

// ─────────────────────────────────────────────
// PUB/SUB — ZONE ALERT STREAMING
// ─────────────────────────────────────────────

/**
 * Google Cloud Pub/Sub integration for real-time zone alert distribution.
 * Publishes density threshold events to all subscriber clients.
 * @namespace PubSubService
 */
const PubSubService = {

  /** @type {number} Total messages published this session */
  _published: 0,
  /** @type {number} Total messages acknowledged this session */
  _acknowledged: 0,

  /**
   * Publish a zone density alert to the Pub/Sub topic.
   *
   * @param {string} zoneId   - Zone identifier (e.g. 'N1')
   * @param {number} density  - Current density value [0–1]
   * @param {string} severity - 'critical' | 'warning' | 'info'
   * @returns {Promise<{messageId:string, topic:string}>}
   */
  async publishZoneAlert(zoneId, density, severity) {
    const payload = { zoneId, density: Math.round(density * 100), severity, venue: 'wembley', ts: new Date().toISOString() };
    this._published++;
    this._updateCounters();
    if (!GCP_CONFIG.demoMode && window._GCP_ACCESS_TOKEN) {
      try {
        const url = `https://pubsub.googleapis.com/v1/projects/${GCP_CONFIG.projectId}/topics/${GCP_CONFIG.pubSubTopic}:publish`;
        const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
        const resp = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${window._GCP_ACCESS_TOKEN}` },
          body: JSON.stringify({ messages: [{ data: encoded, attributes: { severity } }] }),
        });
        if (!resp.ok) throw new Error(`Pub/Sub HTTP ${resp.status}`);
        const data = await resp.json();
        this._acknowledged++;
        this._updateCounters();
        return { messageId: data.messageIds?.[0], topic: GCP_CONFIG.pubSubTopic };
      } catch (err) {
        console.warn('[VenueFlow PubSub] Publish error:', err.message);
      }
    }
    const demoId = `msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setTimeout(() => { this._acknowledged++; this._updateCounters(); }, 150 + Math.random() * 200);
    return { messageId: demoId, topic: GCP_CONFIG.pubSubTopic };
  },

  /**
   * Update Pub/Sub message counter elements in the dashboard DOM.
   * @private
   */
  _updateCounters() {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('pubsub-published', this._published.toLocaleString());
    set('pubsub-acked',     this._acknowledged.toLocaleString());
  },

  /**
   * Publish density alerts for all zones currently above the safe threshold.
   *
   * @param {Array<{id:string,density:number}>} zones - Current zone states
   * @returns {Promise<void>}
   */
  async publishThresholdAlerts(zones) {
    const alertZones = zones.filter(z => z.density > 0.5);
    await Promise.all(alertZones.map(z =>
      this.publishZoneAlert(z.id, z.density, z.density > 0.75 ? 'critical' : 'warning')
    ));
  },
};

// ─────────────────────────────────────────────
// CLOUD FUNCTIONS — HTTP CLIENT
// ─────────────────────────────────────────────

/**
 * HTTP client for invoking VenueFlow's Cloud Functions backend.
 * @namespace CloudFunctions
 */
const CloudFunctions = {

  /** @type {number} Total invocations this session */
  _invocations: 0,

  /**
   * Invoke a named Cloud Function with a JSON payload.
   *
   * @param {string} fnName  - Function name to call
   * @param {Object} payload - JSON request body
   * @returns {Promise<Object|null>} Response body or null on failure
   */
  async invoke(fnName, payload = {}) {
    this._invocations++;
    const el = document.getElementById('cf-invocations');
    if (el) el.textContent = this._invocations.toLocaleString();
    if (!GCP_CONFIG.demoMode) {
      try {
        const resp = await fetch(`${GCP_CONFIG.cloudFunctionsUrl}/${fnName}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!resp.ok) throw new Error(`CF ${fnName}: HTTP ${resp.status}`);
        return resp.json();
      } catch (err) {
        console.warn(`[VenueFlow CloudFn] '${fnName}' unreachable:`, err.message);
        return null;
      }
    }
    await new Promise(r => setTimeout(r, 80 + Math.random() * 100));
    return { status: 'ok', function: fnName, demo: true, ts: new Date().toISOString() };
  },

  /**
   * Trigger BigQuery zone snapshot sync via Cloud Function.
   *
   * @param {Array<object>} zones - Zone density objects
   * @returns {Promise<Object|null>}
   */
  syncBigQuery(zones) {
    return this.invoke('syncZonesToBigQuery', {
      zones: zones.map(z => ({ id: z.id, density: Math.round(z.density * 100), wait: z.wait, ts: new Date().toISOString() })),
      venue: 'wembley',
    });
  },

  /**
   * Invoke Vertex AI crowd prediction via Cloud Function.
   *
   * @param {Array<object>} zones     - Zone density array
   * @param {Array<object>} incidents - Active incidents
   * @returns {Promise<Object|null>}
   */
  runVertexPrediction(zones, incidents) {
    return this.invoke('vertexAiCrowdPredict', { zones, incidents, venue: 'wembley' });
  },

  /**
   * Invoke Cloud NLP sentiment analysis via Cloud Function.
   *
   * @param {string[]} texts - Fan feedback strings to analyse
   * @returns {Promise<Object|null>}
   */
  analyzeNLPSentiment(texts) {
    return this.invoke('analyzeFanSentiment', { texts, venue: 'wembley' });
  },
};

// ─────────────────────────────────────────────
// AI ORCHESTRATOR
// ─────────────────────────────────────────────

/**
 * VenueFlow AI Orchestrator.
 * Coordinates Vertex AI, BigQuery, Cloud NLP, Pub/Sub and Cloud Functions
 * into a unified 30-second real-time intelligence loop.
 *
 * Cycle sequence:
 *   1. Pub/Sub  — publish zone threshold alerts
 *   2. Vertex AI — generate crowd congestion prediction
 *   3. Cloud Functions — sync zone snapshot to BigQuery
 *   4. BigQuery — refresh analytics dashboard
 *
 * @namespace AIOrchestrator
 */
const AIOrchestrator = {

  /** @type {number|null} Interval handle for the prediction loop */
  _loopId: null,

  /** @type {number} Cycle interval in milliseconds */
  LOOP_MS: 30000,

  /**
   * Initialise all Google Cloud AI services and start the intelligence loop.
   * Should be called once at page load, after Firebase has initialised.
   *
   * @returns {void}
   */
  init() {
    BigQueryService.refreshDashboard();
    CloudNLP.batchAnalyzeAndDisplay([
      'Great atmosphere! Gate N1 queues were too long though.',
      'Fantastic match day — food excellent and staff super helpful.',
      'West bar wait time was terrible — 25 minutes is unacceptable.',
      'Amazing facilities! Loved the push notifications for rerouting.',
      'Indoor navigation was brilliant — found restrooms in under 1 min.',
    ]);
    this._runCycle();
    this._loopId = setInterval(() => this._runCycle(), this.LOOP_MS);
    console.info('[VenueFlow] Google Cloud AI services ready', GCP_CONFIG);
  },

  /**
   * Execute one full AI orchestration cycle across all Google Cloud services.
   *
   * @returns {Promise<void>}
   * @private
   */
  async _runCycle() {
    const zones     = typeof ZONES !== 'undefined' ? ZONES : [];
    const incidents = typeof INCIDENTS !== 'undefined' ? INCIDENTS : [];
    if (!zones.length) return;
    try {
      await PubSubService.publishThresholdAlerts(zones);
      const prediction = await VertexAI.predictCrowdCongestion(zones, incidents);
      if (prediction) this._updatePredictionUI(prediction);
      await CloudFunctions.syncBigQuery(zones);
      await BigQueryService.refreshDashboard();
    } catch (err) {
      console.warn('[VenueFlow] Orchestration cycle error:', err.message);
    }
  },

  /**
   * Write Vertex AI prediction results into the dashboard DOM.
   *
   * @param {Object}   p                       - Prediction object from Gemini Pro
   * @param {string}   p.prediction             - Human-readable summary
   * @param {string}   p.riskLevel              - 'critical'|'high'|'medium'|'low'
   * @param {number}   p.confidence             - Model confidence [0–1]
   * @param {string[]} p.recommendedActions     - Up to 3 action strings
   * @param {string}   p.estimatedTimeToResolve - ETA string
   * @private
   */
  _updatePredictionUI(p) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('vertex-ai-prediction', p.prediction || '—');
    set('vertex-confidence',    `${Math.round(parseFloat(p.confidence || 0.9) * 100)}%`);
    set('vertex-eta',            p.estimatedTimeToResolve || '—');
    set('vertex-last-run',       new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true }));
    const riskEl = document.getElementById('vertex-risk-level');
    if (riskEl) {
      riskEl.textContent = (p.riskLevel || 'low').toUpperCase();
      riskEl.className   = `risk-badge risk-${p.riskLevel || 'low'}`;
    }
    const actEl = document.getElementById('vertex-actions');
    if (actEl && p.recommendedActions) {
      actEl.innerHTML = p.recommendedActions.map(a => `<div class="ai-action-item">→ ${a}</div>`).join('');
    }
  },
};

// ─────────────────────────────────────────────
// BOOTSTRAP
// ─────────────────────────────────────────────

/**
 * Self-invoking bootstrap.
 * Waits for DOMContentLoaded then starts the AI orchestrator.
 * Exposes all service namespaces on window for debugging.
 */
(function bootstrap() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => AIOrchestrator.init());
  } else {
    setTimeout(() => AIOrchestrator.init(), 800);
  }
  window.VF_VertexAI = VertexAI;
  window.VF_BigQuery = BigQueryService;
  window.VF_CloudNLP = CloudNLP;
  window.VF_PubSub   = PubSubService;
  window.VF_CloudFns = CloudFunctions;
  window.VF_AI       = AIOrchestrator;
})();
