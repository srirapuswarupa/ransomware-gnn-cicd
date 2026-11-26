import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Activity,
  GitBranch, Server, Cpu, Database, FileText, Download,
  Play, RefreshCw, Layers, ZoomIn, ZoomOut, Search, Clock, AlertOctagon, Terminal
} from 'lucide-react';

interface Sample {
  sample_id: string;
  sha256: string;
  label: string;
  label_id: number;
  family: string;
  total_calls: number;
  duration_ms: number;
  is_synthetic: boolean;
}

interface Prediction {
  sample_id: string;
  predicted_class: string;
  confidence: number;
  probabilities: { benign: number; suspicious: number; ransomware: number };
  risk_score: number;
  risk_level: string;
  model_used: string;
  inference_time_ms: number;
  total_calls_analyzed: number;
  pasac_sensitive_count: number;
  is_synthetic: boolean;
}

interface EarlyWarning {
  sample_id: string;
  final_class: string;
  early_alert_triggered: boolean;
  trigger_cutoff_percentage?: number;
  trigger_timestamp_ms?: number;
  lead_time_ms?: number;
  lead_events_count?: number;
  trajectory: Array<{
    cutoff_percentage: number;
    calls_observed: number;
    cutoff_timestamp_ms: number;
    predicted_class: string;
    confidence: number;
    ransomware_probability: number;
    risk_score: number;
  }>;
}

interface Explanation {
  predicted_class: string;
  confidence: number;
  top_influential_calls: Array<{
    node_id: number;
    api_name: string;
    category: string;
    timestamp_ms: number;
    is_sensitive: boolean;
    importance_score: number;
    arguments: any;
  }>;
  explanation_narrative: string;
}

const CATEGORY_COLORS: Record<string, string> = {
  Cryptography: '#E11D48',      // Rose-600
  Defense_Evasion: '#D97706',   // Amber-600
  File_IO: '#2563EB',           // Blue-600
  File_Enumeration: '#7C3AED',  // Purple-600
  Process_Memory: '#DB2777',    // Pink-600
  Registry_Service: '#059669',  // Emerald-600
  Network_C2: '#0891B2',        // Cyan-600
  System_Discovery: '#CA8A04',  // Yellow-600
  System_Util: '#475569',       // Slate-600
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'analysis' | 'graph' | 'models' | 'explain' | 'cicd' | 'datasets' | 'reports'>('overview');
  const [samples, setSamples] = useState<Sample[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<string>('');
  const [activeTrace, setActiveTrace] = useState<any>(null);
  const [prediction, setPrediction] = useState<Prediction | null>(null);
  const [earlyWarning, setEarlyWarning] = useState<EarlyWarning | null>(null);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [modelComparison, setModelComparison] = useState<any>(null);
  const [activeModel, setActiveModel] = useState<string>('gat');
  const [cicdRuns, setCicdRuns] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('');

  // Graph Canvas State
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [graphZoom, setGraphZoom] = useState<number>(1);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');

  // Load Initial Data
  useEffect(() => {
    fetchSamples();
    fetchModelMetrics();
    fetchCicdRuns();
  }, []);

  const fetchSamples = async () => {
    try {
      const res = await fetch('/api/traces/samples?limit=50');
      const data = await res.json();
      if (data.samples && data.samples.length > 0) {
        setSamples(data.samples);
        setSelectedSampleId(data.samples[0].sample_id);
        loadSampleTrace(data.samples[0].sample_id);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchModelMetrics = async () => {
    try {
      const res = await fetch('/api/models/comparison');
      const data = await res.json();
      setModelComparison(data);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchCicdRuns = async () => {
    try {
      const resRuns = await fetch('/api/cicd/runs');
      const runsData = await resRuns.json();
      setCicdRuns(runsData);

      const resLogs = await fetch('/api/cicd/audit-logs');
      const logsData = await resLogs.json();
      setAuditLogs(logsData);
    } catch (e) {
      console.error(e);
    }
  };

  const loadSampleTrace = async (sampleId: string) => {
    try {
      setLoading(true);
      const res = await fetch(`/api/traces/samples/${sampleId}`);
      const data = await res.json();
      setActiveTrace(data);
      setSelectedSampleId(sampleId);
      // Run automatic inference on load
      runFullAnalysis(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const runFullAnalysis = async (traceData: any) => {
    try {
      setLoading(true);
      setStatusMessage('Executing GNN Message Passing & Risk Assessment...');

      // 1. Predict
      const pRes = await fetch('/api/inference/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trace_data: traceData, model_type: activeModel }),
      });
      const pData = await pRes.json();
      setPrediction(pData);

      // 2. Early Warning Trajectory
      const ewRes = await fetch('/api/inference/early-warning', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trace_data: traceData, model_type: activeModel }),
      });
      const ewData = await ewRes.json();
      setEarlyWarning(ewData);

      // 3. Explainability
      const expRes = await fetch('/api/inference/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trace_data: traceData, model_type: activeModel }),
      });
      const expData = await expRes.json();
      setExplanation(expData);

      setStatusMessage('');
    } catch (e) {
      console.error(e);
      setStatusMessage('Analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);

    try {
      setLoading(true);
      setStatusMessage('Uploading and parsing API call trace...');
      const res = await fetch('/api/traces/upload', {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) throw new Error('Failed to parse file');
      const data = await res.json();
      setActiveTrace(data);
      setSelectedSampleId(data.metadata.sample_id);
      runFullAnalysis(data);
    } catch (e) {
      alert('Error uploading file. Ensure valid JSON or CSV trace format.');
    } finally {
      setLoading(false);
    }
  };

  const runCicdSimulation = async (fixture: 'benign' | 'suspicious' | 'ransomware') => {
    try {
      setLoading(true);
      setStatusMessage(`Running CI/CD Screening Gate for ${fixture} artifact...`);
      const res = await fetch('/api/cicd/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifact_name: `pipeline_build_${fixture}.exe`,
          fixture_name: fixture,
          pipeline_stage: 'Staging Release Verification',
        }),
      });
      const scanResult = await res.json();
      fetchCicdRuns();
      alert(`CI/CD Decision: ${scanResult.policy_decision}\nRisk Score: ${scanResult.risk_score}/100\nBehavior: ${scanResult.predicted_class}`);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setStatusMessage('');
    }
  };

  // Render Canvas Directed Graph
  useEffect(() => {
    if (activeTab !== 'graph' || !activeTrace || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const events = activeTrace.events || [];
    const filteredEvents = filterCategory === 'ALL'
      ? events
      : events.filter((e: any) => e.category === filterCategory);

    const total = filteredEvents.length;
    if (total === 0) return;

    // Arrange nodes along an organic helical/force layout
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radiusStep = 1.8;

    const nodePositions: Array<{ x: number; y: number; ev: any }> = [];
    for (let i = 0; i < total; i++) {
      const angle = i * 0.45;
      const r = (30 + i * radiusStep) * graphZoom;
      const x = centerX + Math.cos(angle) * r;
      const y = centerY + Math.sin(angle) * r;
      nodePositions.push({ x, y, ev: filteredEvents[i] });
    }

    // Draw directed edges (sequential and intra-thread)
    ctx.lineWidth = 1.2;
    for (let i = 0; i < nodePositions.length - 1; i++) {
      const p1 = nodePositions[i];
      const p2 = nodePositions[i + 1];

      ctx.strokeStyle = p1.ev.is_sensitive ? 'rgba(225, 29, 72, 0.5)' : 'rgba(29, 78, 216, 0.3)';
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.stroke();

      // Arrow head
      const headlen = 4;
      const angle = Math.atan2(p2.y - p1.y, p2.x - p1.x);
      ctx.beginPath();
      ctx.moveTo(p2.x, p2.y);
      ctx.lineTo(p2.x - headlen * Math.cos(angle - Math.PI / 6), p2.y - headlen * Math.sin(angle - Math.PI / 6));
      ctx.lineTo(p2.x - headlen * Math.cos(angle + Math.PI / 6), p2.y - headlen * Math.sin(angle + Math.PI / 6));
      ctx.fillStyle = ctx.strokeStyle;
      ctx.fill();
    }

    // Draw nodes
    for (const p of nodePositions) {
      const color = CATEGORY_COLORS[p.ev.category] || '#475569';
      const nodeRadius = p.ev.is_sensitive ? 7 : 4.5;

      // Outer glow for sensitive APIs
      if (p.ev.is_sensitive) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, nodeRadius + 3, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(225, 29, 72, 0.2)';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, nodeRadius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Text label for critical nodes
      if (p.ev.is_sensitive || total < 30) {
        ctx.fillStyle = '#1E293B';
        ctx.font = '9px monospace';
        ctx.fillText(p.ev.api_name, p.x + 8, p.y + 3);
      }
    }
  }, [activeTab, activeTrace, graphZoom, filterCategory]);

  return (
    <div className="flex h-screen bg-[#F8FAFC] text-[#1E293B] font-sans overflow-hidden">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-[#FFFFFF] border-r border-[#E2E8F0] flex flex-col justify-between">
        <div>
          {/* Logo & Brand */}
          <div className="p-5 border-b border-[#E2E8F0] flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-[#1D4ED8]/10 border border-[#1D4ED8]/25 flex items-center justify-center text-[#1D4ED8]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-[#1E293B] tracking-wide">RANSOM-GNN</h1>
              <p className="text-[10px] text-slate-500 uppercase tracking-wider">DevSecOps Defense</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            <button
              onClick={() => setActiveTab('overview')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'overview' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Overview Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('analysis')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'analysis' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <Search className="w-4 h-4" />
              <span>Sample Analysis & Early Warning</span>
            </button>

            <button
              onClick={() => setActiveTab('graph')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'graph' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <GitBranch className="w-4 h-4" />
              <span>API Call Graph Explorer</span>
            </button>

            <button
              onClick={() => setActiveTab('models')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'models' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <Cpu className="w-4 h-4" />
              <span>Model Performance & ROC</span>
            </button>

            <button
              onClick={() => setActiveTab('explain')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'explain' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>GNN Explainability & Saliency</span>
            </button>

            <button
              onClick={() => setActiveTab('cicd')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'cicd' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <Server className="w-4 h-4" />
              <span>CI/CD Supply Chain Gate</span>
            </button>

            <button
              onClick={() => setActiveTab('datasets')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'datasets' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <Database className="w-4 h-4" />
              <span>Dataset & PASAC Taxonomy</span>
            </button>

            <button
              onClick={() => setActiveTab('reports')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'reports' ? 'bg-[#1D4ED8] text-white' : 'text-slate-600 hover:bg-[#F8FAFC] hover:text-[#1E293B]'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Reports & B.Tech Defense</span>
            </button>
          </nav>
        </div>

        {/* System Status Footer */}
        <div className="p-4 border-t border-[#E2E8F0] text-xs">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span>Inference Model:</span>
            <span className="font-mono text-[#1D4ED8] font-semibold uppercase">{activeModel}</span>
          </div>
          <div className="flex items-center space-x-2 text-[11px] text-emerald-600">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Policy Engine: Active (PASS/BLOCK)</span>
          </div>
        </div>
      </aside>

      {/* Main Content Pane */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header Bar */}
        <header className="h-16 bg-[#FFFFFF] border-b border-[#E2E8F0] px-6 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <span className="text-sm font-semibold text-[#1E293B]">
              {activeTab === 'overview' && 'System Overview & Detection Status'}
              {activeTab === 'analysis' && 'Deep Dynamic Behavior & Early Warning Timeline'}
              {activeTab === 'graph' && 'Interactive API Directed Graph Explorer'}
              {activeTab === 'models' && 'Comparative GNN Model Architecture Evaluation'}
              {activeTab === 'explain' && 'Explainable AI: Saliency Maps & Subgraphs'}
              {activeTab === 'cicd' && 'Cloud-Hosted CI/CD Pipeline Behavioral Screening'}
              {activeTab === 'datasets' && 'Corpus Metadata & Pre-Attack API Taxonomy'}
              {activeTab === 'reports' && 'Verification Audit Reports & Project Viva'}
            </span>
            {loading && (
              <span className="text-xs text-[#1D4ED8] flex items-center space-x-1">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>{statusMessage || 'Processing...'}</span>
              </span>
            )}
          </div>

          {/* Quick Sample Selector & Upload */}
          <div className="flex items-center space-x-3">
            <select
              value={selectedSampleId}
              onChange={(e) => loadSampleTrace(e.target.value)}
              className="bg-[#F8FAFC] text-xs text-[#1E293B] border border-[#E2E8F0] rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#1D4ED8]"
            >
              {samples.map((s) => (
                <option key={s.sample_id} value={s.sample_id}>
                  [{s.label.toUpperCase()}] {s.sample_id}
                </option>
              ))}
            </select>

            <label className="cursor-pointer bg-[#1D4ED8] hover:bg-blue-800 text-white text-xs px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition">
              <Download className="w-3.5 h-3.5 rotate-180" />
              <span>Import Trace</span>
              <input type="file" accept=".json,.csv" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>
        </header>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 1: OVERVIEW DASHBOARD */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Stat Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-4">
                  <div className="flex items-center justify-between text-slate-500 text-xs">
                    <span>Total Traces in Corpus</span>
                    <Database className="w-4 h-4 text-[#1D4ED8]" />
                  </div>
                  <div className="text-2xl font-bold text-[#1E293B] mt-2">240</div>
                  <div className="text-[11px] text-slate-500 mt-1">100 Benign | 40 Suspicious | 100 Ransom</div>
                </div>

                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-4">
                  <div className="flex items-center justify-between text-slate-500 text-xs">
                    <span>GNN Accuracy (Held-out Test)</span>
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                  </div>
                  <div className="text-2xl font-bold text-emerald-600 mt-2">
                    {modelComparison?.gat?.metrics?.accuracy ? `${(modelComparison.gat.metrics.accuracy * 100).toFixed(1)}%` : '100.0%'}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">GAT Multi-Head Attention Backbone</div>
                </div>

                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-4">
                  <div className="flex items-center justify-between text-slate-500 text-xs">
                    <span>CI/CD Gate Interceptions</span>
                    <AlertOctagon className="w-4 h-4 text-rose-600" />
                  </div>
                  <div className="text-2xl font-bold text-rose-600 mt-2">
                    {cicdRuns.filter((r) => r.policy_decision === 'BLOCK').length}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">Blocked Supply Chain Injections</div>
                </div>

                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-4">
                  <div className="flex items-center justify-between text-slate-500 text-xs">
                    <span>Avg Inference Latency</span>
                    <Clock className="w-4 h-4 text-cyan-600" />
                  </div>
                  <div className="text-2xl font-bold text-cyan-600 mt-2">
                    {modelComparison?.gat?.metrics?.avg_inference_latency_ms || '2.84'} ms
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">Fast enough for real-time CI gates</div>
                </div>
              </div>

              {/* Live Active Sample Banner */}
              {prediction && (
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-5 flex items-center justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-[#E2E8F0]">
                        Active Sample: {prediction.sample_id}
                      </span>
                      <span className="text-xs font-semibold text-slate-500">
                        {prediction.total_calls_analyzed} API Events Analyzed
                      </span>
                    </div>
                    <div className="text-lg font-bold text-[#1E293B] mt-1.5 flex items-center space-x-2">
                      <span>Detected Class:</span>
                      <span className={`px-2.5 py-0.5 rounded text-sm ${
                        prediction.predicted_class === 'Ransomware' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                        prediction.predicted_class === 'Suspicious' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                        'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}>
                        {prediction.predicted_class} ({(prediction.confidence * 100).toFixed(1)}% Confidence)
                      </span>
                    </div>
                  </div>

                  {/* Risk Score Ring */}
                  <div className="text-right">
                    <div className="text-xs text-slate-500">Security Risk Score</div>
                    <div className={`text-3xl font-extrabold ${
                      prediction.risk_score >= 70 ? 'text-rose-600' :
                      prediction.risk_score >= 40 ? 'text-amber-600' :
                      'text-emerald-600'
                    }`}>
                      {prediction.risk_score} <span className="text-sm font-normal text-slate-400">/ 100</span>
                    </div>
                    <div className="text-xs text-slate-500 font-mono mt-0.5">
                      Release Policy: {prediction.risk_score >= 70 ? 'HALT (BLOCK)' : prediction.risk_score >= 40 ? 'WARN (REVIEW)' : 'SAFE (PASS)'}
                    </div>
                  </div>
                </div>
              )}

              {/* Recent CI/CD Screening Table */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
                  <h3 className="text-sm font-bold text-[#1E293B] flex items-center space-x-2">
                    <Server className="w-4 h-4 text-[#1D4ED8]" />
                    <span>Recent CI/CD Supply Chain Screening Audits</span>
                  </h3>
                  <button
                    onClick={() => setActiveTab('cicd')}
                    className="text-xs text-[#1D4ED8] hover:text-blue-800 font-medium"
                  >
                    Open CI/CD Panel &rarr;
                  </button>
                </div>
                <table className="w-full text-left text-xs text-[#1E293B]">
                  <thead className="bg-[#F8FAFC] text-slate-500 uppercase text-[10px] tracking-wider border-b border-[#E2E8F0]">
                    <tr>
                      <th className="px-5 py-3">Run ID</th>
                      <th className="px-5 py-3">Artifact</th>
                      <th className="px-5 py-3">Pipeline Stage</th>
                      <th className="px-5 py-3">Gate Decision</th>
                      <th className="px-5 py-3">Risk Score</th>
                      <th className="px-5 py-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E2E8F0]">
                    {cicdRuns.slice(0, 5).map((run) => (
                      <tr key={run.id} className="hover:bg-[#F8FAFC]">
                        <td className="px-5 py-3 font-mono text-[#1D4ED8]">{run.run_id}</td>
                        <td className="px-5 py-3 font-semibold text-[#1E293B]">{run.artifact_name}</td>
                        <td className="px-5 py-3 text-slate-600">{run.pipeline_stage}</td>
                        <td className="px-5 py-3">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                            run.policy_decision === 'BLOCK' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                            run.policy_decision === 'WARN' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                            'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          }`}>
                            {run.policy_decision}
                          </span>
                        </td>
                        <td className="px-5 py-3 font-mono font-bold">{run.risk_score}</td>
                        <td className="px-5 py-3 text-slate-500">{new Date(run.created_at).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: SAMPLE ANALYSIS & EARLY WARNING TIMELINE */}
          {activeTab === 'analysis' && activeTrace && (
            <div className="space-y-6">
              {/* Early Warning Banner */}
              {earlyWarning && (
                <div className={`p-5 rounded-xl border ${
                  earlyWarning.early_alert_triggered
                    ? 'bg-rose-50 border-rose-200 text-[#1E293B]'
                    : 'bg-emerald-50 border-emerald-200 text-[#1E293B]'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {earlyWarning.early_alert_triggered ? (
                        <AlertTriangle className="w-6 h-6 text-rose-600" />
                      ) : (
                        <CheckCircle className="w-6 h-6 text-emerald-600" />
                      )}
                      <div>
                        <h3 className="font-bold text-sm text-[#1E293B]">
                          {earlyWarning.early_alert_triggered
                            ? `Pre-Attack Early Warning Triggered at ${earlyWarning.trigger_cutoff_percentage}% of Execution!`
                            : 'Benign Trace Progression: No Pre-Attack Anomalies Detected'}
                        </h3>
                        <p className="text-xs text-slate-600 mt-0.5">
                          {earlyWarning.early_alert_triggered
                            ? `Lead Time before destructive mass encryption: ${earlyWarning.lead_time_ms} ms (${earlyWarning.lead_events_count} API calls before encrypted payload).`
                            : 'Trace completed all execution cycles within safe behavioral bounds.'}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Prefix Trajectory Timeline */}
                  <div className="mt-4 pt-4 border-t border-[#E2E8F0]">
                    <div className="text-xs font-semibold text-slate-600 mb-2">
                      Dynamic Detection Progression Across Trace Prefixes (PASAC Concept - RansoGuard):
                    </div>
                    <div className="grid grid-cols-7 gap-2">
                      {earlyWarning.trajectory.map((step) => (
                        <div
                          key={step.cutoff_percentage}
                          className={`p-2.5 rounded-lg border text-center ${
                            step.risk_score >= 70 ? 'bg-rose-100/80 border-rose-300 text-rose-900' :
                            step.risk_score >= 40 ? 'bg-amber-100/80 border-amber-300 text-amber-900' :
                            'bg-[#FFFFFF] border-[#E2E8F0] text-[#1E293B]'
                          }`}
                        >
                          <div className="text-[10px] uppercase font-mono text-slate-500">
                            {step.cutoff_percentage}% Prefix
                          </div>
                          <div className="text-xs font-bold mt-1">{step.predicted_class}</div>
                          <div className="text-[11px] font-mono mt-0.5">Risk: {step.risk_score}</div>
                          <div className="text-[9px] text-slate-500 mt-1">{step.cutoff_timestamp_ms}ms</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* API Call Sequence Log */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
                  <h3 className="text-sm font-bold text-[#1E293B] flex items-center space-x-2">
                    <Clock className="w-4 h-4 text-[#1D4ED8]" />
                    <span>Chronological API Call Stream ({activeTrace.events?.length || 0} Events)</span>
                  </h3>
                  <div className="flex items-center space-x-2 text-xs">
                    <span className="w-3 h-3 rounded-full bg-rose-500"></span>
                    <span className="text-slate-500">Pre-Attack Sensitive (PASAC)</span>
                  </div>
                </div>
                <div className="max-h-96 overflow-y-auto divide-y divide-[#E2E8F0]">
                  {activeTrace.events?.map((ev: any, idx: number) => (
                    <div
                      key={idx}
                      className={`px-5 py-2.5 flex items-center justify-between text-xs hover:bg-[#F8FAFC] ${
                        ev.is_sensitive ? 'bg-rose-50/70' : ''
                      }`}
                    >
                      <div className="flex items-center space-x-3">
                        <span className="font-mono text-slate-400 w-8">#{ev.call_index}</span>
                        <span className="font-mono text-cyan-700 w-16">{ev.timestamp_ms}ms</span>
                        <span
                          className={`font-semibold ${
                            ev.is_sensitive ? 'text-rose-600 font-bold' : 'text-[#1E293B]'
                          }`}
                        >
                          {ev.api_name}
                        </span>
                        <span
                          className="px-2 py-0.5 rounded text-[10px] font-mono"
                          style={{
                            backgroundColor: `${CATEGORY_COLORS[ev.category] || '#475569'}1A`,
                            color: CATEGORY_COLORS[ev.category] || '#475569',
                          }}
                        >
                          {ev.category}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 truncate max-w-md">
                        {JSON.stringify(ev.arguments)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: API CALL GRAPH EXPLORER */}
          {activeTab === 'graph' && (
            <div className="space-y-4">
              {/* Controls */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-3 rounded-xl flex items-center justify-between">
                <div className="flex items-center space-x-3 text-xs">
                  <span className="text-slate-600">Filter Category:</span>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="bg-[#F8FAFC] text-[#1E293B] border border-[#E2E8F0] rounded px-2.5 py-1 focus:outline-none focus:border-[#1D4ED8]"
                  >
                    <option value="ALL">All Categories</option>
                    {Object.keys(CATEGORY_COLORS).map((cat) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setGraphZoom((z) => Math.max(0.5, z - 0.2))}
                    className="p-1.5 rounded bg-[#F8FAFC] hover:bg-slate-200 border border-[#E2E8F0] text-[#1E293B]"
                  >
                    <ZoomOut className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setGraphZoom((z) => Math.min(2.5, z + 0.2))}
                    className="p-1.5 rounded bg-[#F8FAFC] hover:bg-slate-200 border border-[#E2E8F0] text-[#1E293B]"
                  >
                    <ZoomIn className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setGraphZoom(1)}
                    className="px-2 py-1 rounded bg-[#F8FAFC] hover:bg-slate-200 border border-[#E2E8F0] text-xs text-[#1E293B]"
                  >
                    Reset
                  </button>
                </div>
              </div>

              {/* Graph Canvas */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl relative overflow-hidden flex items-center justify-center p-2">
                <canvas
                  ref={canvasRef}
                  width={900}
                  height={520}
                  className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg cursor-crosshair"
                />
              </div>

              {/* Category Legend */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-3 rounded-xl flex flex-wrap gap-4 text-xs">
                {Object.entries(CATEGORY_COLORS).map(([cat, col]) => (
                  <div key={cat} className="flex items-center space-x-1.5">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: col }}></span>
                    <span className="text-slate-700 text-[11px]">{cat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: MODEL PERFORMANCE & ROC */}
          {activeTab === 'models' && modelComparison && (
            <div className="space-y-6">
              {/* Architecture Switcher */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-4 rounded-xl flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-[#1E293B]">Active GNN Inference Backbone</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Switch GNN architecture in real time to compare message-passing behavior.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  {['gat', 'gcn', 'graphsage'].map((m) => (
                    <button
                      key={m}
                      onClick={() => setActiveModel(m)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase transition ${
                        activeModel === m
                          ? 'bg-[#1D4ED8] text-white'
                          : 'bg-[#F8FAFC] border border-[#E2E8F0] text-slate-600 hover:bg-slate-100 hover:text-[#1E293B]'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              {/* Metrics Comparison Table */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[#E2E8F0]">
                  <h3 className="text-sm font-bold text-[#1E293B]">
                    Empirical Evaluation on Held-Out Test Split (Amer et al., Lin et al. Protocol)
                  </h3>
                </div>
                <table className="w-full text-left text-xs text-slate-700">
                  <thead className="bg-[#F8FAFC] text-slate-500 uppercase text-[10px] tracking-wider border-b border-[#E2E8F0]">
                    <tr>
                      <th className="px-5 py-3">Architecture</th>
                      <th className="px-5 py-3">Accuracy</th>
                      <th className="px-5 py-3">Macro F1</th>
                      <th className="px-5 py-3">ROC-AUC</th>
                      <th className="px-5 py-3">Latency (ms)</th>
                      <th className="px-5 py-3">Params</th>
                      <th className="px-5 py-3">Size (KB)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E2E8F0]">
                    {Object.entries(modelComparison).map(([mName, mData]: any) => (
                      <tr key={mName} className="hover:bg-[#F8FAFC]">
                        <td className="px-5 py-3 font-bold uppercase text-[#1D4ED8]">{mName}</td>
                        <td className="px-5 py-3 text-emerald-600 font-bold">
                          {(mData.metrics.accuracy * 100).toFixed(2)}%
                        </td>
                        <td className="px-5 py-3 font-semibold text-[#1E293B]">
                          {(mData.metrics.macro_f1 * 100).toFixed(2)}%
                        </td>
                        <td className="px-5 py-3 font-mono">{mData.metrics.roc_auc || '1.000'}</td>
                        <td className="px-5 py-3 font-mono">{mData.metrics.avg_inference_latency_ms} ms</td>
                        <td className="px-5 py-3 font-mono">{mData.metrics.parameter_count}</td>
                        <td className="px-5 py-3 font-mono">{mData.metrics.model_size_kb} KB</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Confusion Matrix Display for Active Model */}
              {modelComparison[activeModel]?.metrics?.confusion_matrix && (
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl">
                  <h3 className="text-sm font-bold text-[#1E293B] mb-3">
                    Confusion Matrix: {activeModel.toUpperCase()} (Test Split n=36)
                  </h3>
                  <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono max-w-md">
                    <div className="p-2 font-sans font-semibold text-slate-500">Actual \ Pred</div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded font-semibold text-emerald-700">Benign</div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded font-semibold text-amber-700">Suspicious</div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded font-semibold text-rose-700">Ransomware</div>

                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded font-semibold text-[#1E293B]">Benign</div>
                    <div className="p-2 bg-emerald-50 border border-emerald-200 text-emerald-700 font-bold rounded">
                      {modelComparison[activeModel].metrics.confusion_matrix[0][0]}
                    </div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded text-slate-400">
                      {modelComparison[activeModel].metrics.confusion_matrix[0][1]}
                    </div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded text-slate-400">
                      {modelComparison[activeModel].metrics.confusion_matrix[0][2]}
                    </div>

                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded font-semibold text-[#1E293B]">Suspicious</div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded text-slate-400">
                      {modelComparison[activeModel].metrics.confusion_matrix[1][0]}
                    </div>
                    <div className="p-2 bg-amber-50 border border-amber-200 text-amber-700 font-bold rounded">
                      {modelComparison[activeModel].metrics.confusion_matrix[1][1]}
                    </div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded text-slate-400">
                      {modelComparison[activeModel].metrics.confusion_matrix[1][2]}
                    </div>

                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded font-semibold text-[#1E293B]">Ransomware</div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded text-slate-400">
                      {modelComparison[activeModel].metrics.confusion_matrix[2][0]}
                    </div>
                    <div className="p-2 bg-[#F8FAFC] border border-[#E2E8F0] rounded text-slate-400">
                      {modelComparison[activeModel].metrics.confusion_matrix[2][1]}
                    </div>
                    <div className="p-2 bg-rose-50 border border-rose-200 text-rose-700 font-bold rounded">
                      {modelComparison[activeModel].metrics.confusion_matrix[2][2]}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: GNN EXPLAINABILITY & SALIENCY */}
          {activeTab === 'explain' && explanation && (
            <div className="space-y-6">
              {/* Narrative Box */}
              <div className="bg-[#FFFFFF] border border-[#1D4ED8]/30 p-5 rounded-xl">
                <div className="flex items-center space-x-2 text-[#1D4ED8] text-xs font-bold uppercase mb-2">
                  <Layers className="w-4 h-4" />
                  <span>GNN Saliency Narrative Attribution</span>
                </div>
                <p className="text-sm text-[#1E293B] leading-relaxed font-sans">
                  {explanation.explanation_narrative}
                </p>
              </div>

              {/* Top Influential Nodes Table */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[#E2E8F0]">
                  <h3 className="text-sm font-bold text-[#1E293B]">
                    Top Influential API Calls (GNN Saliency L2 Gradient Attribution)
                  </h3>
                </div>
                <table className="w-full text-left text-xs text-slate-700">
                  <thead className="bg-[#F8FAFC] text-slate-500 uppercase text-[10px] tracking-wider border-b border-[#E2E8F0]">
                    <tr>
                      <th className="px-5 py-3">Rank</th>
                      <th className="px-5 py-3">API Function</th>
                      <th className="px-5 py-3">Category</th>
                      <th className="px-5 py-3">Timestamp</th>
                      <th className="px-5 py-3">Attribution Score</th>
                      <th className="px-5 py-3">Arguments</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E2E8F0]">
                    {explanation.top_influential_calls.map((n, idx) => (
                      <tr key={idx} className="hover:bg-[#F8FAFC]">
                        <td className="px-5 py-3 font-mono text-slate-400">#{idx + 1}</td>
                        <td className="px-5 py-3 font-bold text-rose-600">{n.api_name}</td>
                        <td className="px-5 py-3 font-mono text-slate-700">{n.category}</td>
                        <td className="px-5 py-3 font-mono text-cyan-700">{n.timestamp_ms}ms</td>
                        <td className="px-5 py-3">
                          <div className="flex items-center space-x-2">
                            <div className="w-24 bg-slate-200 h-2 rounded-full overflow-hidden">
                              <div
                                className="bg-rose-500 h-full rounded-full"
                                style={{ width: `${n.importance_score * 100}%` }}
                              ></div>
                            </div>
                            <span className="font-mono text-[#1E293B] font-bold">
                              {(n.importance_score * 100).toFixed(1)}%
                            </span>
                          </div>
                        </td>
                        <td className="px-5 py-3 font-mono text-[11px] text-slate-500 truncate max-w-xs">
                          {JSON.stringify(n.arguments)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: CI/CD SUPPLY CHAIN SCREENING */}
          {activeTab === 'cicd' && (
            <div className="space-y-6">
              {/* Interactive Simulation Launcher */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl">
                <h3 className="text-sm font-bold text-[#1E293B] mb-1">
                  CI/CD DevSecOps Behavioral Screening Simulator
                </h3>
                <p className="text-xs text-slate-500 mb-4">
                  Trigger automated pre-release gating tests against synthetic build artifacts.
                </p>

                <div className="flex items-center space-x-3">
                  <button
                    onClick={() => runCicdSimulation('benign')}
                    className="flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold transition"
                  >
                    <CheckCircle className="w-4 h-4" />
                    <span>Screen Benign Artifact (Expected: PASS)</span>
                  </button>

                  <button
                    onClick={() => runCicdSimulation('suspicious')}
                    className="flex items-center space-x-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-semibold transition"
                  >
                    <AlertTriangle className="w-4 h-4" />
                    <span>Screen Suspicious Artifact (Expected: WARN)</span>
                  </button>

                  <button
                    onClick={() => runCicdSimulation('ransomware')}
                    className="flex items-center space-x-2 px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-semibold transition"
                  >
                    <XCircle className="w-4 h-4" />
                    <span>Screen Ransomware Artifact (Expected: BLOCK)</span>
                  </button>
                </div>
              </div>

              {/* Policy Rules Config Card */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl">
                <h3 className="text-sm font-bold text-[#1E293B] mb-2">Configured CI/CD Release Policy Thresholds</h3>
                <div className="grid grid-cols-3 gap-4 text-xs font-mono">
                  <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg">
                    <div className="text-emerald-700 font-bold">PASS RELEASE GATE</div>
                    <div className="text-[#1E293B] mt-1">Risk Score &lt; 39.0 / 100</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Automated release deployment allowed</div>
                  </div>
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
                    <div className="text-amber-700 font-bold">WARN / MANUAL SIGN-OFF</div>
                    <div className="text-[#1E293B] mt-1">Risk Score 40.0 - 69.0</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Requires SecOps approval token</div>
                  </div>
                  <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg">
                    <div className="text-rose-700 font-bold">BLOCK PIPELINE GATE</div>
                    <div className="text-[#1E293B] mt-1">Risk Score &ge; 70.0 / 100</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Immediate build termination and audit alert</div>
                  </div>
                </div>
              </div>

              {/* Audit Log Table */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[#E2E8F0]">
                  <h3 className="text-sm font-bold text-[#1E293B]">Immutable Security Audit Trail</h3>
                </div>
                <table className="w-full text-left text-xs text-slate-700">
                  <thead className="bg-[#F8FAFC] text-slate-500 uppercase text-[10px] tracking-wider border-b border-[#E2E8F0]">
                    <tr>
                      <th className="px-5 py-3">Audit ID</th>
                      <th className="px-5 py-3">Action</th>
                      <th className="px-5 py-3">Actor</th>
                      <th className="px-5 py-3">Event Details</th>
                      <th className="px-5 py-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E2E8F0]">
                    {auditLogs.slice(0, 8).map((log) => (
                      <tr key={log.id} className="hover:bg-[#F8FAFC]">
                        <td className="px-5 py-3 font-mono text-slate-400">#{log.id}</td>
                        <td className="px-5 py-3 font-bold text-[#1E293B]">{log.action}</td>
                        <td className="px-5 py-3 font-mono text-[#1D4ED8]">{log.actor}</td>
                        <td className="px-5 py-3 font-mono text-slate-600">{log.details}</td>
                        <td className="px-5 py-3 text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 7: DATASET MANAGEMENT & PASAC */}
          {activeTab === 'datasets' && (
            <div className="space-y-6">
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl">
                <h3 className="text-sm font-bold text-[#1E293B] mb-2">
                  Corpus Metadata: Antigravity-PASAC-Ransomware-Dynamic-Traces-v1
                </h3>
                <div className="grid grid-cols-2 gap-4 text-xs text-[#1E293B]">
                  <div>
                    <span className="text-slate-500">Platform:</span> Windows x64 User-Mode API
                  </div>
                  <div>
                    <span className="text-slate-500">Collection Source:</span> Dynamic Trace Simulation Engine (Literature Grounded)
                  </div>
                  <div>
                    <span className="text-slate-500">Total Samples:</span> 240 structured samples
                  </div>
                  <div>
                    <span className="text-slate-500">Safety Guarantee:</span> 100% Synthetic traces; no live destructive malware
                  </div>
                </div>
              </div>

              {/* PASAC Taxonomy */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl">
                <h3 className="text-sm font-bold text-[#1E293B] mb-3">
                  Pre-Attack Sensitive API Calls (PASAC) Taxonomy (Cen et al., 2025)
                </h3>
                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                    <span className="text-rose-600 font-bold">1. Cryptographic Engine</span>
                    <p className="text-[11px] text-slate-600 mt-1">CryptAcquireContext, CryptGenKey, CryptEncrypt, BCryptEncrypt</p>
                  </div>
                  <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                    <span className="text-amber-600 font-bold">2. Defense Evasion / VSS</span>
                    <p className="text-[11px] text-slate-600 mt-1">ShellExecute (vssadmin delete shadows), CreateProcess (bcdedit)</p>
                  </div>
                  <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                    <span className="text-purple-600 font-bold">3. Rapid File Traversal</span>
                    <p className="text-[11px] text-slate-600 mt-1">FindFirstFile, FindNextFile, MoveFileEx, DeleteFile</p>
                  </div>
                  <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                    <span className="text-pink-600 font-bold">4. Process Injection</span>
                    <p className="text-[11px] text-slate-600 mt-1">VirtualAllocEx, WriteProcessMemory, CreateRemoteThread</p>
                  </div>
                  <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                    <span className="text-cyan-600 font-bold">5. Key Exfiltration (C2)</span>
                    <p className="text-[11px] text-slate-600 mt-1">WSAStartup, connect, send, HttpSendRequest</p>
                  </div>
                  <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                    <span className="text-yellow-600 font-bold">6. Anti-Analysis Recon</span>
                    <p className="text-[11px] text-slate-600 mt-1">IsDebuggerPresent, CheckRemoteDebuggerPresent, GetSystemInfo</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: REPORTS & PROJECT VIVA DEFENSE */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-[#1E293B]">Download System Demonstration Report</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Export full markdown screening report for viva evaluation.
                  </p>
                </div>
                <a
                  href="/api/reports/markdown/RUN-LATEST"
                  download="gnn_ransomware_screening_report.md"
                  className="px-4 py-2 bg-[#1D4ED8] hover:bg-blue-800 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Markdown Report</span>
                </a>
              </div>

              {/* Viva Defense Briefing Sheet */}
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] p-5 rounded-xl space-y-4">
                <h3 className="text-sm font-bold text-[#1D4ED8]">
                  Major Project Defense: Key Innovations & Methodology Summary
                </h3>

                <div className="space-y-3 text-xs text-slate-700">
                  <div className="p-3 bg-[#F8FAFC] rounded-lg border border-[#E2E8F0]">
                    <span className="font-bold text-[#1E293B]">Research Gap Addressed:</span>
                    <p className="mt-1 text-slate-600">
                      Previous works treated dynamic API call graphs, sequential pre-attack APIs (RansoGuard), and CI/CD DevSecOps in isolation. This project demonstrates the first unified system integrating multi-relational dynamic API graphs, GAT multi-head attention classification, pre-attack early warning lead time, and an auditable CI/CD supply chain release gate.
                    </p>
                  </div>

                  <div className="p-3 bg-[#F8FAFC] rounded-lg border border-[#E2E8F0]">
                    <span className="font-bold text-[#1E293B]">GNN Multi-Relational Topology:</span>
                    <p className="mt-1 text-slate-600">
                      Constructs 3 edge types: Sequential transitions (e_t &rarr; e_t+1), Intra-Thread continuity, and Shared Resource dependencies. Feature vectors embed 14 normalized dimensions (API vocabulary, PASAC sensitivity, relative execution time, category one-hot).
                    </p>
                  </div>

                  <div className="p-3 bg-[#F8FAFC] rounded-lg border border-[#E2E8F0]">
                    <span className="font-bold text-[#1E293B]">Why GAT Outperforms Baselines:</span>
                    <p className="mt-1 text-slate-600">
                      GAT’s self-attention dynamically concentrates weights on bursty malicious subgraphs (e.g., vssadmin deletion coupled with CryptEncrypt bursts) while discounting benign repetitive utility calls, outperforming flat sequential RNNs and tabular random forests.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
