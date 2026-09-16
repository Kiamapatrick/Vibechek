import { http, HttpResponse } from 'msw';
import type {
  ScanResponse,
  ScanRequest,
  FindingResponse,
  TriageRunResponse,
  TriageCompareResponse,
  FindingsStats,
  ScanStatus,
  SeverityLevel,
  TriageMode,
} from '@/types/api';

const scanId = 'scan-123';
const triageId = 'triage-456';

const mockScan: ScanResponse = {
  scan_id: scanId,
  status: 'completed',
  progress: {
    pages_crawled: 10,
    findings_found: 5,
    errors: 0,
  },
  created_at: '2024-01-15T10:00:00Z',
  updated_at: '2024-01-15T10:05:00Z',
  target_url: 'https://example.com',
};

const mockScans: ScanResponse[] = [
  mockScan,
  {
    ...mockScan,
    scan_id: 'scan-456',
    status: 'running',
    progress: { pages_crawled: 5, findings_found: 2, errors: 0 },
    created_at: '2024-01-15T11:00:00Z',
    updated_at: '2024-01-15T11:02:00Z',
    target_url: 'https://test.com',
  },
];

const severities: SeverityLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

const mockFindings: FindingResponse[] = [
  {
    id: 'finding-1',
    scan_id: scanId,
    check: 'xss_reflected',
    title: 'Reflected XSS in search parameter',
    severity: 'Critical',
    score: 9.1,
    impact: 9,
    likelihood: 8,
    wstg_id: 'WSTG-INPV-01',
    attck_ids: ['T1059.007'],
    evidence: {
      url: 'https://example.com/search?q=<script>alert(1)</script>',
      snippet: '<script>alert(1)</script>',
      request_headers: {},
      response_headers: {},
      response_status: 200,
    },
    confidence: 0.95,
    remediation: 'Implement proper input validation and output encoding',
    references: ['https://owasp.org/www-community/attacks/xss/'],
    created_at: '2024-01-15T10:03:00Z',
  },
  {
    id: 'finding-2',
    scan_id: scanId,
    check: 'sql_injection',
    title: 'SQL Injection in login form',
    severity: 'High',
    score: 8.5,
    impact: 9,
    likelihood: 7,
    wstg_id: 'WSTG-INPV-05',
    attck_ids: ['T1190'],
    evidence: {
      url: 'https://example.com/login',
      snippet: "' OR '1'='1",
      request_headers: {},
      response_headers: {},
      response_status: 200,
    },
    confidence: 0.9,
    remediation: 'Use parameterized queries',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
    created_at: '2024-01-15T10:03:30Z',
  },
  {
    id: 'finding-3',
    scan_id: scanId,
    check: 'csrf',
    title: 'Missing CSRF protection on state-changing endpoint',
    severity: 'Medium',
    score: 6.8,
    impact: 6,
    likelihood: 7,
    wstg_id: 'WSTG-SESS-05',
    attck_ids: [],
    evidence: {
      url: 'https://example.com/transfer',
      snippet: '<form action="/transfer" method="POST">',
      request_headers: {},
      response_headers: {},
      response_status: 200,
    },
    confidence: 0.8,
    remediation: 'Implement CSRF tokens',
    references: ['https://owasp.org/www-community/attacks/csrf'],
    created_at: '2024-01-15T10:04:00Z',
  },
  {
    id: 'finding-4',
    scan_id: scanId,
    check: 'info_disclosure',
    title: 'Server version disclosed in headers',
    severity: 'Low',
    score: 3.2,
    impact: 3,
    likelihood: 4,
    wstg_id: 'WSTG-INFO-02',
    attck_ids: [],
    evidence: {
      url: 'https://example.com/',
      snippet: 'Server: Apache/2.4.41',
      request_headers: {},
      response_headers: { server: 'Apache/2.4.41' },
      response_status: 200,
    },
    confidence: 0.99,
    remediation: 'Hide server version in headers',
    references: [],
    created_at: '2024-01-15T10:04:30Z',
  },
  {
    id: 'finding-5',
    scan_id: scanId,
    check: 'cookie_flags',
    title: 'Session cookie missing Secure and HttpOnly flags',
    severity: 'Info',
    score: 1.5,
    impact: 2,
    likelihood: 2,
    wstg_id: 'WSTG-SESS-02',
    attck_ids: [],
    evidence: {
      url: 'https://example.com/',
      snippet: 'Set-Cookie: session=abc123; Path=/',
      request_headers: {},
      response_headers: { 'set-cookie': 'session=abc123; Path=/' },
      response_status: 200,
    },
    confidence: 1.0,
    remediation: 'Add Secure and HttpOnly flags to cookies',
    references: ['https://owasp.org/www-community/controls/SecureFlag'],
    created_at: '2024-01-15T10:05:00Z',
  },
];

const mockStats: FindingsStats = {
  by_severity: {
    Critical: 1,
    High: 1,
    Medium: 1,
    Low: 1,
    Info: 1,
  },
  by_check: {
    xss_reflected: 1,
    sql_injection: 1,
    csrf: 1,
    info_disclosure: 1,
    cookie_flags: 1,
  },
};

const mockTriageRuns: TriageRunResponse[] = [
  {
    triage_id: triageId,
    scan_id: scanId,
    mode: 'baseline',
    status: 'completed',
    results: [
      {
        finding_id: 'finding-1',
        finding_title: 'Reflected XSS in search parameter',
        explanation: 'The search parameter reflects user input without sanitization, allowing script execution.',
        exploitability: 8,
        fix: 'Implement context-aware output encoding for HTML contexts.',
        revised_priority: 5,
        source: 'baseline',
        prompt_version: 'v1.0.0',
        original_severity: 'Critical',
      },
      {
        finding_id: 'finding-2',
        finding_title: 'SQL Injection in login form',
        explanation: 'User input directly concatenated into SQL query without parameterization.',
        exploitability: 9,
        fix: 'Use prepared statements with parameterized queries.',
        revised_priority: 5,
        source: 'baseline',
        prompt_version: 'v1.0.0',
        original_severity: 'High',
      },
    ],
    created_at: '2024-01-15T10:10:00Z',
    completed_at: '2024-01-15T10:10:30Z',
  },
  {
    triage_id: 'triage-789',
    scan_id: scanId,
    mode: 'llm',
    status: 'completed',
    results: [
      {
        finding_id: 'finding-1',
        finding_title: 'Reflected XSS in search parameter',
        explanation: 'The search endpoint reflects unsanitized user input directly in the response body, enabling reflected XSS attacks.',
        exploitability: 9,
        fix: 'Encode user input when rendering in HTML context. Use CSP header as defense-in-depth.',
        revised_priority: 5,
        source: 'llm',
        prompt_version: 'v1.0.0',
        original_severity: 'Critical',
      },
      {
        finding_id: 'finding-2',
        finding_title: 'SQL Injection in login form',
        explanation: 'The login form concatenates user input directly into SQL query string, allowing authentication bypass and data extraction.',
        exploitability: 10,
        fix: 'Use parameterized queries. Implement WAF rules for SQL injection patterns.',
        revised_priority: 5,
        source: 'llm',
        prompt_version: 'v1.0.0',
        original_severity: 'High',
      },
      {
        finding_id: 'finding-3',
        finding_title: 'Missing CSRF protection on state-changing endpoint',
        explanation: 'The transfer endpoint lacks CSRF tokens, allowing attackers to forge requests on behalf of authenticated users.',
        exploitability: 7,
        fix: 'Implement synchronizer token pattern. Add SameSite=Strict to session cookies.',
        revised_priority: 4,
        source: 'llm',
        prompt_version: 'v1.0.0',
        original_severity: 'Medium',
      },
    ],
    created_at: '2024-01-15T10:15:00Z',
    completed_at: '2024-01-15T10:16:00Z',
  },
];

const mockCompare: TriageCompareResponse = {
  scan_id: scanId,
  baseline: mockTriageRuns[0].results,
  llm: mockTriageRuns[1].results,
  baseline_only: [],
  llm_only: ['finding-3'],
  changed_priority: [
    { finding_id: 'finding-3', baseline_priority: 0, llm_priority: 4 },
  ],
};

const mockReportPlain = `VibeShield Security Scan Report
===============================

Target: https://example.com
Scan ID: ${scanId}
Date: 2024-01-15T10:05:00Z
Status: completed

Findings Summary:
- Critical: 1
- High: 1
- Medium: 1
- Low: 1
- Info: 1

Detailed Findings:
1. [Critical] Reflected XSS in search parameter
   Check: xss_reflected
   Score: 9.1
   URL: https://example.com/search?q=<script>alert(1)</script>
   Remediation: Implement proper input validation and output encoding

2. [High] SQL Injection in login form
   Check: sql_injection
   Score: 8.5
   URL: https://example.com/login
   Remediation: Use parameterized queries
`;

const mockReportJson = {
  scan_id: scanId,
  target_url: 'https://example.com',
  status: 'completed',
  created_at: '2024-01-15T10:00:00Z',
  completed_at: '2024-01-15T10:05:00Z',
  findings: mockFindings,
  stats: mockStats,
};

export const handlers = [
  // Scans
  http.get('/api/scans', ({ request }) => {
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    const limit = parseInt(url.searchParams.get('limit') || '100');
    let data = mockScans;
    if (status) {
      data = data.filter(s => s.status === status);
    }
    return HttpResponse.json(data.slice(0, limit));
  }),

  http.post('/api/scans', async ({ request }) => {
    const body = await request.json() as ScanRequest;
    const newScan: ScanResponse = {
      scan_id: `scan-${Date.now()}`,
      status: 'pending',
      progress: { pages_crawled: 0, findings_found: 0, errors: 0 },
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      target_url: body.url,
    };
    return HttpResponse.json(newScan, { status: 201 });
  }),

  http.get(`/api/scans/${scanId}`, () => HttpResponse.json(mockScan)),
  http.get('/api/scans/:scanId', ({ params }) => {
    const { scanId } = params;
    const scan = mockScans.find(s => s.scan_id === scanId);
    if (!scan) return HttpResponse.json({ error: 'Not found' }, { status: 404 });
    return HttpResponse.json(scan);
  }),

  // Findings
  http.get(`/api/scans/${scanId}/findings`, () => HttpResponse.json(mockFindings)),
  http.get('/api/scans/:scanId/findings', ({ params, request }) => {
    const { scanId } = params;
    const url = new URL(request.url);
    const severity = url.searchParams.get('severity');
    const check = url.searchParams.get('check');
    let data = mockFindings.filter(f => f.scan_id === scanId);
    if (severity) data = data.filter(f => f.severity === severity);
    if (check) data = data.filter(f => f.check === check);
    return HttpResponse.json(data);
  }),

  http.get(`/api/scans/${scanId}/findings/stats`, () => HttpResponse.json(mockStats)),
  http.get('/api/scans/:scanId/findings/stats', ({ params }) => {
    const { scanId } = params;
    const findings = mockFindings.filter(f => f.scan_id === scanId);
    const by_severity: Record<SeverityLevel, number> = {
      Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0,
    };
    const by_check: Record<string, number> = {};
    findings.forEach(f => {
      by_severity[f.severity]++;
      by_check[f.check] = (by_check[f.check] || 0) + 1;
    });
    return HttpResponse.json({ by_severity, by_check });
  }),

  // Triage
  http.post('/api/scans/:scanId/triage', async ({ params, request }) => {
    const { scanId } = params;
    const url = new URL(request.url);
    const mode = url.searchParams.get('mode') as TriageMode;
    const run: TriageRunResponse = {
      triage_id: `triage-${Date.now()}`,
      scan_id: scanId as string,
      mode,
      status: 'completed',
      results: mockTriageRuns.find(r => r.mode === mode)?.results || [],
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    };
    return HttpResponse.json(run, { status: 201 });
  }),

  http.get(`/api/scans/${scanId}/triage`, () => HttpResponse.json(mockTriageRuns)),
  http.get('/api/scans/:scanId/triage', ({ params }) => {
    const { scanId } = params;
    return HttpResponse.json(mockTriageRuns.filter(r => r.scan_id === scanId));
  }),

  http.get(`/api/scans/${scanId}/triage/compare`, () => HttpResponse.json(mockCompare)),
  http.get('/api/scans/:scanId/triage/compare', ({ params }) => {
    const { scanId } = params;
    return HttpResponse.json({ ...mockCompare, scan_id: scanId as string });
  }),

  http.get(`/api/triage/${triageId}`, () => {
    const run = mockTriageRuns.find(r => r.triage_id === triageId);
    if (!run) return HttpResponse.json({ error: 'Not found' }, { status: 404 });
    return HttpResponse.json(run);
  }),

  // Report
  http.get('/api/scans/:scanId/report', ({ params, request }) => {
    const { scanId } = params;
    const url = new URL(request.url);
    const format = url.searchParams.get('format') as 'plain' | 'json' | 'both';
    if (format === 'plain') {
      return new HttpResponse(mockReportPlain, {
        headers: { 'Content-Type': 'text/plain' },
      });
    }
    if (format === 'json') {
      return HttpResponse.json(mockReportJson);
    }
    return HttpResponse.json({ plain: mockReportPlain, json: mockReportJson });
  }),

  // KB Context
  http.get('/api/triage/kb-context', () => HttpResponse.json({ context: 'Mock KB context' })),
];

export const errorHandlers = [
  http.post('/api/scans', () => HttpResponse.json({ error: 'Invalid URL' }, { status: 400 })),
  http.get('/api/scans/:scanId', () => HttpResponse.json({ error: 'Not found' }, { status: 404 })),
];