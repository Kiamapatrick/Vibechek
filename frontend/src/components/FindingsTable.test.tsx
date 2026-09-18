import { renderWithProviders, screen, waitFor } from '@/test/utils';
import userEvent from '@testing-library/user-event';
import { FindingsTable } from '@/components/FindingsTable';
import type { FindingResponse, SeverityLevel } from '@/types/api';

const mockFindings: FindingResponse[] = [
  {
    id: 'finding-1',
    scan_id: 'scan-123',
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
    scan_id: 'scan-123',
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
    scan_id: 'scan-123',
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
    scan_id: 'scan-123',
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
    scan_id: 'scan-123',
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

const mockSeverityStats: Record<SeverityLevel, number> = {
  Critical: 1,
  High: 1,
  Medium: 1,
  Low: 1,
  Info: 1,
};

const mockCheckStats = {
  xss_reflected: 1,
  sql_injection: 1,
  csrf: 1,
  info_disclosure: 1,
  cookie_flags: 1,
};

describe('FindingsTable', () => {
  const user = userEvent.setup();

  beforeEach(() => {
    renderWithProviders(
      <FindingsTable findings={mockFindings} stats={mockSeverityStats} />
    );
  });

  it('renders all findings in severity order (Critical -> High -> Medium -> Low -> Info)', () => {
    const rows = screen.getAllByRole('row');
    const dataRows = rows.slice(1); // Skip header

    expect(dataRows).toHaveLength(5);
    expect(dataRows[0]).toHaveTextContent('Critical');
    expect(dataRows[1]).toHaveTextContent('High');
    expect(dataRows[2]).toHaveTextContent('Medium');
    expect(dataRows[3]).toHaveTextContent('Low');
    expect(dataRows[4]).toHaveTextContent('Info');
  });

  it('shows correct stats in severity filter dropdown', () => {
    const selects = screen.getAllByRole('combobox');
    const severitySelect = selects[0];
    const options = severitySelect.querySelectorAll('option');

    expect(options[0]).toHaveTextContent('All Severities');
    expect(options[1]).toHaveTextContent('Critical (1)');
    expect(options[2]).toHaveTextContent('High (1)');
    expect(options[3]).toHaveTextContent('Medium (1)');
    expect(options[4]).toHaveTextContent('Low (1)');
    expect(options[5]).toHaveTextContent('Info (1)');
  });

  it('filters by severity', async () => {
    const selects = screen.getAllByRole('combobox');
    const severitySelect = selects[0];
    await userEvent.selectOptions(severitySelect, 'Critical');

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toHaveTextContent('Critical');
      expect(rows[0]).toHaveTextContent('Reflected XSS');
    });
  });

  it('filters by search term', async () => {
    const searchInput = screen.getByPlaceholderText('Search findings...');
    await user.type(searchInput, 'XSS');

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toHaveTextContent('Reflected XSS');
    });
  });

  it('filters by check type', async () => {
    const selects = screen.getAllByRole('combobox');
    const checkSelect = selects[1];
    await userEvent.selectOptions(checkSelect, 'sql_injection');

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toHaveTextContent('SQL Injection');
    });
  });

  it('sorts by severity ascending when clicking header', async () => {
    const severityHeader = screen.getByRole('columnheader', { name: /severity/i });
    await user.click(severityHeader);

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows[0]).toHaveTextContent('Info');
      expect(rows[4]).toHaveTextContent('Critical');
    });
  });

  it('sorts by severity descending when clicking header again', async () => {
    const severityHeader = screen.getByRole('columnheader', { name: /severity/i });
    await user.click(severityHeader); // asc
    await user.click(severityHeader); // desc

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows[0]).toHaveTextContent('Critical');
      expect(rows[4]).toHaveTextContent('Info');
    });
  });

  it('sorts by check name', async () => {
    const checkHeader = screen.getByRole('columnheader', { name: /check/i });
    await user.click(checkHeader);

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows[0]).toHaveTextContent('cookie_flags');
      expect(rows[4]).toHaveTextContent('xss_reflected');
    });
  });

  it('sorts by title', async () => {
    const titleHeader = screen.getByRole('columnheader', { name: /title/i });
    await user.click(titleHeader);

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows[0]).toHaveTextContent('Missing CSRF');
      expect(rows[4]).toHaveTextContent('SQL Injection');
    }, { timeout: 3000 });
  });

  it('sorts by score', async () => {
    const scoreHeader = screen.getByRole('columnheader', { name: /score/i });
    await user.click(scoreHeader);

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows[0]).toHaveTextContent('1.5');
      expect(rows[4]).toHaveTextContent('9.1');
    });
  });

  it('sorts by confidence', async () => {
    const confidenceHeader = screen.getByRole('columnheader', { name: /confidence/i });
    await user.click(confidenceHeader);

    await waitFor(() => {
      const rows = screen.getAllByRole('row').slice(1);
      expect(rows[0]).toHaveTextContent('80%');
      expect(rows[4]).toHaveTextContent('100%');
    });
  });

  it('shows clear filters button when filters are active', async () => {
    const searchInput = screen.getByPlaceholderText('Search findings...');
    await user.type(searchInput, 'XSS');

    expect(screen.getByText('Clear filters')).toBeInTheDocument();
  });

  it('clears all filters when clear button clicked', async () => {
    const searchInput = screen.getByPlaceholderText('Search findings...');
    await user.type(searchInput, 'XSS');

    const clearButton = screen.getByText('Clear filters');
    await user.click(clearButton);

    expect(searchInput).toHaveValue('');
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows).toHaveLength(5);
  });

  it('shows correct finding count', () => {
    expect(screen.getByText('Showing 5 of 5 findings')).toBeInTheDocument();
  });

  it('shows filtered count correctly', async () => {
    const searchInput = screen.getByPlaceholderText('Search findings...');
    await user.type(searchInput, 'XSS');

    expect(screen.getByText('Showing 1 of 5 findings')).toBeInTheDocument();
  });

  it('renders evidence URL truncated', () => {
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('https://example.com/search?q=<script>alert(1)</scr');
  });

  it('handles empty findings', () => {
    const { unmount } = renderWithProviders(
      <FindingsTable findings={[]} stats={mockSeverityStats} />
    );

    expect(screen.getByText('No findings match the current filters')).toBeInTheDocument();
  });

  it('calls onSort callback when provided', async () => {
    const onSort = jest.fn();
    const { unmount } = renderWithProviders(
      <FindingsTable findings={mockFindings} stats={mockSeverityStats} onSort={onSort} />
    );

    const severityHeaders = screen.getAllByRole('columnheader', { name: /severity/i });
    const tableSeverityHeader = severityHeaders[1]; // Second one is in thead
    await user.click(tableSeverityHeader);

    expect(onSort).toHaveBeenCalledWith('severity', 'asc');
  });
});