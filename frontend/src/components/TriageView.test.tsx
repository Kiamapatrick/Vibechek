import { renderWithProviders, screen, waitFor } from '@/test/utils';
import userEvent from '@testing-library/user-event';
import { TriageView } from '@/components/TriageView';
import { api } from '@/lib/api';
import { TriageRunResponse, TriageResult, TriageCompareResponse } from '@/types/api';

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

const mockTriageRuns: TriageRunResponse[] = [
  {
    triage_id: 'triage-1',
    scan_id: scanId,
    mode: 'baseline',
    status: 'completed',
    results: [
      {
        finding_id: 'finding-1',
        finding_title: 'Finding 1',
        explanation: 'Baseline explanation',
        exploitability: 8,
        fix: 'Baseline fix',
        revised_priority: 5,
        source: 'baseline',
        prompt_version: 'v1.0.0',
        original_severity: 'Critical',
      },
    ],
    created_at: '2024-01-15T10:00:00Z',
    completed_at: '2024-01-15T10:00:30Z',
  },
  {
    triage_id: 'triage-2',
    scan_id: scanId,
    mode: 'llm',
    status: 'completed',
    results: [
      {
        finding_id: 'finding-1',
        finding_title: 'Finding 1',
        explanation: 'LLM explanation',
        exploitability: 9,
        fix: 'LLM fix',
        revised_priority: 5,
        source: 'llm',
        prompt_version: 'v1.0.0',
        original_severity: 'Critical',
      },
      {
        finding_id: 'finding-2',
        finding_title: 'Finding 2',
        explanation: 'LLM only finding',
        exploitability: 7,
        fix: 'LLM fix 2',
        revised_priority: 4,
        source: 'llm',
        prompt_version: 'v1.0.0',
        original_severity: 'High',
      },
    ],
    created_at: '2024-01-15T10:10:00Z',
    completed_at: '2024-01-15T10:11:00Z',
  },
];

const mockCompare: TriageCompareResponse = {
  scan_id: scanId,
  baseline: mockTriageRuns[0].results,
  llm: mockTriageRuns[1].results,
  baseline_only: [],
  llm_only: ['finding-2'],
  changed_priority: [],
};

describe('TriageView', () => {
  const user = userEvent.setup();

  beforeEach(() => {
    jest.clearAllMocks();
    (api.listTriageRuns as jest.Mock).mockResolvedValue([]);
    (api.compareTriage as jest.Mock).mockResolvedValue({
      scan_id: scanId,
      baseline: [],
      llm: [],
      baseline_only: [],
      llm_only: [],
      changed_priority: [],
    });
  });

  it('renders Runs and Compare tabs', async () => {
    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Runs')).toBeInTheDocument();
      expect(screen.getByText('Compare')).toBeInTheDocument();
    });
  });

  it('shows Run Baseline and Run LLM Triage buttons', async () => {
    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
      expect(screen.getByText('Run LLM Triage')).toBeInTheDocument();
    });
  });

  it('starts baseline triage', async () => {
    const mockRun: TriageRunResponse = {
      triage_id: 'triage-new-123',
      scan_id: scanId,
      mode: 'baseline',
      status: 'completed',
      results: [
        {
          finding_id: 'finding-1',
          finding_title: 'Test Finding',
          explanation: 'Test explanation',
          exploitability: 8,
          fix: 'Test fix',
          revised_priority: 5,
          source: 'baseline',
          prompt_version: 'v1.0.0',
          original_severity: 'Critical',
        },
      ],
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    };

    (api.startTriage as jest.Mock).mockResolvedValue(mockRun);
    (api.listTriageRuns as jest.Mock).mockResolvedValue([mockRun]);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Run Baseline'));

    await waitFor(() => {
      expect(api.startTriage).toHaveBeenCalledWith(scanId, 'baseline');
    });
  });

  it('starts LLM triage', async () => {
    const mockRun: TriageRunResponse = {
      triage_id: 'triage-new-456',
      scan_id: scanId,
      mode: 'llm',
      status: 'completed',
      results: [
        {
          finding_id: 'finding-1',
          finding_title: 'Test Finding',
          explanation: 'LLM explanation',
          exploitability: 9,
          fix: 'LLM fix',
          revised_priority: 5,
          source: 'llm',
          prompt_version: 'v1.0.0',
          original_severity: 'Critical',
        },
      ],
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    };

    (api.startTriage as jest.Mock).mockResolvedValue(mockRun);
    (api.listTriageRuns as jest.Mock).mockResolvedValue([mockRun]);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run LLM Triage')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Run LLM Triage'));

    await waitFor(() => {
      expect(api.startTriage).toHaveBeenCalledWith(scanId, 'llm');
    });
  });

  it('switches to Compare tab', async () => {
    (api.listTriageRuns as jest.Mock).mockResolvedValue(mockTriageRuns);
    (api.compareTriage as jest.Mock).mockResolvedValue(mockCompare);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Compare'));

    await waitFor(() => {
      expect(screen.getByText('Baseline vs LLM Comparison')).toBeInTheDocument();
      expect(screen.getByText('Baseline Only')).toBeInTheDocument();
      expect(screen.getByText('LLM Only')).toBeInTheDocument();
      expect(screen.getByText('Changed Priority')).toBeInTheDocument();
    });
  });

  it('shows LLM only findings in compare', async () => {
    (api.listTriageRuns as jest.Mock).mockResolvedValue(mockTriageRuns);
    (api.compareTriage as jest.Mock).mockResolvedValue(mockCompare);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Compare'));

    await waitFor(() => {
      expect(screen.getByText('LLM Only')).toBeInTheDocument();
      expect(screen.getByText('1')).toBeInTheDocument();
    });
  });

  it('shows priority changes in compare', async () => {
    const compareWithChanges: TriageCompareResponse = {
      ...mockCompare,
      changed_priority: [
        { finding_id: 'finding-1', baseline_priority: 3, llm_priority: 5 },
      ],
    };

    (api.listTriageRuns as jest.Mock).mockResolvedValue(mockTriageRuns);
    (api.compareTriage as jest.Mock).mockResolvedValue(compareWithChanges);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Compare'));

    await waitFor(() => {
      expect(screen.getByText('Priority Changes')).toBeInTheDocument();
      expect(screen.getByText('finding-1')).toBeInTheDocument();
      expect(screen.getByText('Medium')).toBeInTheDocument();
      expect(screen.getByText('Critical')).toBeInTheDocument();
    });
  });

  it('switches back to Runs tab', async () => {
    (api.listTriageRuns as jest.Mock).mockResolvedValue(mockTriageRuns);
    (api.compareTriage as jest.Mock).mockResolvedValue(mockCompare);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Compare'));
    await waitFor(() => {
      expect(screen.getByText('Baseline vs LLM Comparison')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Runs'));
    await waitFor(() => {
      expect(screen.getByText('Run Baseline')).toBeInTheDocument();
    });
  });

  it('shows error when triage fails', async () => {
    (api.listTriageRuns as jest.Mock).mockResolvedValue([
      {
        triage_id: 'triage-1',
        scan_id: scanId,
        mode: 'baseline',
        status: 'failed',
        error: 'Groq API key not configured',
        results: [],
        created_at: '2024-01-15T10:00:00Z',
      },
    ]);

    renderWithProviders(<TriageView scanId={scanId} />);

    await waitFor(() => {
      expect(screen.getByText('Error: Groq API key not configured')).toBeInTheDocument();
    });
  });
});