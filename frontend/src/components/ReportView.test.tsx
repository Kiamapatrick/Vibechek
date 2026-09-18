import { renderWithProviders, screen, waitFor } from '@/test/utils';
import userEvent from '@testing-library/user-event';
import { ReportView } from '@/components/ReportView';
import { api } from '@/lib/api';

jest.mock('@/lib/api', () => ({
  api: {
    startScan: jest.fn(),
    listScans: jest.fn(),
    getScan: jest.fn(),
    getFindings: jest.fn(),
    getFindingsStats: jest.fn(),
    startTriage: jest.fn(),
    listTriageRuns: jest.fn(),
    getTriage: jest.fn(),
    compareTriage: jest.fn(),
    getReport: jest.fn(),
    getKbContext: jest.fn(),
  },
}));

const scanId = 'scan-123';

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
   Remediation: Implement proper input validation and output encoding`;

const mockReportJson = {
  scan_id: scanId,
  target_url: 'https://example.com',
  status: 'completed',
  created_at: '2024-01-15T10:00:00Z',
  completed_at: '2024-01-15T10:05:00Z',
  findings: [],
  stats: {
    by_severity: { Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1 },
    by_check: { xss_reflected: 1 },
  },
};

const mockReportBoth = {
  plain: mockReportPlain,
  json: mockReportJson,
};

const originalCreateElement = document.createElement.bind(document);

const setupReportMocks = (plain = mockReportPlain, json = mockReportJson, both = mockReportBoth) => {
  (api.getReport as jest.Mock).mockImplementation((_scanId: string, format: string) => {
    if (format === 'plain') return Promise.resolve(plain);
    if (format === 'json') return Promise.resolve(json);
    if (format === 'both') return Promise.resolve(both);
    return Promise.resolve(plain);
  });
};

describe('ReportView', () => {
  const user = userEvent.setup();

  beforeEach(() => {
    jest.clearAllMocks();
    setupReportMocks();
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: jest.fn() },
      configurable: true,
    });
  });

  it('renders format tabs', async () => {
    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Plain')).toBeInTheDocument();
      expect(screen.getByText('Json')).toBeInTheDocument();
      expect(screen.getByText('Both')).toBeInTheDocument();
    });
  });

  it('loads plain format by default', async () => {
    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
      expect(screen.getByText(/Reflected XSS in search parameter/)).toBeInTheDocument();
    });
  });

  it('switches to JSON format', async () => {
    setupReportMocks(mockReportPlain, mockReportJson, mockReportBoth);

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Json'));

    await waitFor(() => {
      expect(screen.getByText(/scan_id/)).toBeInTheDocument();
      expect(screen.getByText(/target_url/)).toBeInTheDocument();
    });
  });

  it('switches to Both format', async () => {
    setupReportMocks(mockReportPlain, mockReportJson, mockReportBoth);

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Both'));

    await waitFor(() => {
      expect(screen.getByText('Plain Text')).toBeInTheDocument();
      expect(screen.getByText('JSON')).toBeInTheDocument();
    });
  });

  it('copies plain format to clipboard', async () => {
    const { container } = renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /copy/i }));

    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(mockReportPlain);
      const checkIcon = container.querySelector('.lucide-check');
      expect(checkIcon).toBeInTheDocument();
    });
  });

  it('copies JSON format to clipboard', async () => {
    setupReportMocks(mockReportPlain, mockReportJson, mockReportBoth);

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Json'));

    await waitFor(() => {
      expect(screen.getByText(/scan_id/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Copy'));

    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(JSON.stringify(mockReportJson, null, 2));
    });
  });

  it('copies Both format to clipboard', async () => {
    setupReportMocks(mockReportPlain, mockReportJson, mockReportBoth);

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Both'));

    await waitFor(() => {
      expect(screen.getByText('Plain Text')).toBeInTheDocument();
      expect(screen.getByText('JSON')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Copy'));

    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        expect.stringContaining('VibeShield Security Scan Report')
      );
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        expect.stringContaining('scan_id')
      );
    });
  });

  it('downloads plain format as .txt', async () => {
    const clickMock = jest.fn();
    const createElementMock = jest.spyOn(document, 'createElement').mockImplementation((tag) => {
      if (tag === 'a') {
        return { href: '', download: '', click: clickMock } as unknown as HTMLAnchorElement;
      }
      return originalCreateElement(tag);
    });

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Download'));

    await waitFor(() => {
      expect(createElementMock).toHaveBeenCalledWith('a');
      expect(clickMock).toHaveBeenCalled();
      expect(global.URL.createObjectURL).toHaveBeenCalled();
      expect(global.URL.revokeObjectURL).toHaveBeenCalled();
    });

    createElementMock.mockRestore();
  });

  it('downloads JSON format as .json', async () => {
    setupReportMocks(mockReportPlain, mockReportJson, mockReportBoth);

    const clickMock = jest.fn();
    const createElementMock = jest.spyOn(document, 'createElement').mockImplementation((tag) => {
      if (tag === 'a') {
        return { href: '', download: '', click: clickMock } as unknown as HTMLAnchorElement;
      }
      return originalCreateElement(tag);
    });

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Json'));

    await waitFor(() => {
      expect(screen.getByText(/scan_id/)).toBeInTheDocument();
    });

    await user.click(screen.getByText('Download'));

    await waitFor(() => {
      expect(clickMock).toHaveBeenCalled();
    });

    createElementMock.mockRestore();
  });

  it('shows loading state', async () => {
    let resolveReport: (value: unknown) => void;
    const reportPromise = new Promise(resolve => { resolveReport = resolve; });
    (api.getReport as jest.Mock).mockImplementation(() => reportPromise);

    renderWithProviders(<ReportView scanId={scanId} />);

    expect(screen.getByText('Loading report...')).toBeInTheDocument();

    resolveReport!(mockReportPlain);
    await waitFor(() => {
      expect(screen.queryByText('Loading report...')).not.toBeInTheDocument();
    });
  });

  it('shows error state', async () => {
    (api.getReport as jest.Mock).mockImplementation(() => 
      new Promise((_, reject) => setTimeout(() => reject(new Error('Failed')), 0))
    );

    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Loading report...')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText('Failed to load report')).toBeInTheDocument();
    }, { timeout: 5000 });
  });

  it('highlights active format tab', async () => {
    renderWithProviders(<ReportView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText(/VibeShield Security Scan Report/)).toBeInTheDocument();
    });

    const plainTab = screen.getByText('Plain');
    expect(plainTab).toHaveClass('bg-white');

    await user.click(screen.getByText('Json'));
    const jsonTab = screen.getByText('Json');
    expect(jsonTab).toHaveClass('bg-white');
  });
});