import { renderWithProviders, screen, waitFor } from '@/test/utils';
import userEvent from '@testing-library/user-event';
import { fireEvent } from '@testing-library/react';
import { ScanWizard } from '@/components/ScanWizard';
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

describe('ScanWizard', () => {
  const user = userEvent.setup();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders all form fields', () => {
    renderWithProviders(<ScanWizard />);

    expect(screen.getByLabelText('Target URL')).toBeInTheDocument();
    expect(screen.getByLabelText('Max Pages')).toBeInTheDocument();
    expect(screen.getByLabelText('Max Depth')).toBeInTheDocument();
    expect(screen.getByLabelText('Timeout (seconds)')).toBeInTheDocument();
    expect(screen.getByLabelText('Allow write tests (may create test data on target)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start scan/i })).toBeInTheDocument();
  });

  it('blocks submission with empty URL via HTML5 validation', async () => {
    renderWithProviders(<ScanWizard />);

    const submitButton = screen.getByRole('button', { name: /start scan/i });
    await user.click(submitButton);

    expect(screen.getByLabelText('Target URL')).toHaveAttribute('required');
    expect(screen.getByLabelText('Target URL')).toHaveAttribute('type', 'url');
  });

  it('disables submit button when URL is empty', () => {
    renderWithProviders(<ScanWizard />);

    const submitButton = screen.getByRole('button', { name: /start scan/i });
    expect(submitButton).toBeDisabled();
  });

  it('enables submit button when URL is filled', async () => {
    renderWithProviders(<ScanWizard />);

    const urlInput = screen.getByLabelText('Target URL');
    await user.type(urlInput, 'https://example.com');

    const submitButton = screen.getByRole('button', { name: /start scan/i });
    expect(submitButton).not.toBeDisabled();
  });

  it('clamps maxPages to 1-1000 range', async () => {
    renderWithProviders(<ScanWizard />);

    const maxPagesInput = screen.getByLabelText('Max Pages');

    await user.clear(maxPagesInput);
    fireEvent.change(maxPagesInput, { target: { value: '0' } });
    await waitFor(() => expect(maxPagesInput).toHaveValue(1));

    await user.clear(maxPagesInput);
    fireEvent.change(maxPagesInput, { target: { value: '1001' } });
    await waitFor(() => expect(maxPagesInput).toHaveValue(1000));

    fireEvent.change(maxPagesInput, { target: { value: '500' } });
    await waitFor(() => expect(maxPagesInput).toHaveValue(500));
  });

  it('clamps maxDepth to 0-10 range', async () => {
    renderWithProviders(<ScanWizard />);

    const maxDepthInput = screen.getByLabelText('Max Depth');

    await user.clear(maxDepthInput);
    fireEvent.change(maxDepthInput, { target: { value: '-1' } });
    await waitFor(() => expect(maxDepthInput).toHaveValue(0));

    await user.clear(maxDepthInput);
    fireEvent.change(maxDepthInput, { target: { value: '11' } });
    await waitFor(() => expect(maxDepthInput).toHaveValue(10));
  });

  it('clamps timeout to 1-300 range', async () => {
    renderWithProviders(<ScanWizard />);

    const timeoutInput = screen.getByLabelText('Timeout (seconds)');

    await user.clear(timeoutInput);
    fireEvent.change(timeoutInput, { target: { value: '0' } });
    await waitFor(() => expect(timeoutInput).toHaveValue(1));

    await user.clear(timeoutInput);
    fireEvent.change(timeoutInput, { target: { value: '301' } });
    await waitFor(() => expect(timeoutInput).toHaveValue(300));
  });

  it('shows warning when allow_write_tests is enabled', async () => {
    renderWithProviders(<ScanWizard />);

    const checkbox = screen.getByLabelText('Allow write tests (may create test data on target)');
    expect(checkbox).not.toBeChecked();

    await user.click(checkbox);
    expect(checkbox).toBeChecked();
  });

  it('submits form and redirects on success', async () => {
    const mockScan = {
      scan_id: 'scan-new-123',
      status: 'pending' as const,
      progress: { pages_crawled: 0, findings_found: 0, errors: 0 },
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      target_url: 'https://example.com',
    };

    (api.startScan as jest.Mock).mockResolvedValue(mockScan);

    renderWithProviders(<ScanWizard />);

    const urlInput = screen.getByLabelText('Target URL');
    await user.type(urlInput, 'https://example.com');

    const submitButton = screen.getByRole('button', { name: /start scan/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(api.startScan).toHaveBeenCalledWith({
        url: 'https://example.com',
        max_pages: 20,
        max_depth: 2,
        timeout: 10,
        allow_write_tests: false,
      });
    });
  });

  it('shows error message on submission failure', async () => {
    (api.startScan as jest.Mock).mockRejectedValue(new Error('Invalid URL'));

    renderWithProviders(<ScanWizard />);

    const urlInput = screen.getByLabelText('Target URL');
    await user.type(urlInput, 'https://invalid.com');

    const submitButton = screen.getByRole('button', { name: /start scan/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Invalid URL')).toBeInTheDocument();
    });
  });

  it('shows loading state during submission', async () => {
    let resolveSubmit: (value: unknown) => void;
    const submitPromise = new Promise(resolve => { resolveSubmit = resolve; });

    (api.startScan as jest.Mock).mockImplementation(() => submitPromise);

    renderWithProviders(<ScanWizard />);

    const urlInput = screen.getByLabelText('Target URL');
    await user.type(urlInput, 'https://example.com');

    const submitButton = screen.getByRole('button', { name: /start scan/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Starting scan...')).toBeInTheDocument();
      expect(submitButton).toBeDisabled();
    });

    resolveSubmit!({ scan_id: 'scan-123' });
    await waitFor(() => expect(screen.queryByText('Starting scan...')).not.toBeInTheDocument());
  });
});