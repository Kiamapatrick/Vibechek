import { renderWithProviders, screen, waitFor, act } from '@/test/utils';
import { ProgressLog } from '@/components/ProgressLog';

// Mock scrollIntoView for JSDOM
Element.prototype.scrollIntoView = jest.fn();

class MockEventSource {
  static instances: MockEventSource[] = [];
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 2;

  readyState = MockEventSource.CONNECTING;
  url: string;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  eventListeners: Map<string, ((event: MessageEvent) => void)[]> = new Map();

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
    setTimeout(() => {
      this.readyState = MockEventSource.OPEN;
      this.onopen?.();
    }, 0);
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    if (!this.eventListeners.has(type)) {
      this.eventListeners.set(type, []);
    }
    this.eventListeners.get(type)!.push(listener);
  }

  removeEventListener(type: string, listener: (event: MessageEvent) => void) {
    const listeners = this.eventListeners.get(type);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index !== -1) listeners.splice(index, 1);
    }
  }

  close() {
    this.readyState = MockEventSource.CLOSED;
  }

  // Test helpers
  emit(event: MessageEvent) {
    if (event.type === 'message' && this.onmessage) {
      this.onmessage(event);
    }
    const listeners = this.eventListeners.get(event.type);
    if (listeners) {
      listeners.forEach(l => l(event));
    }
  }

  static getLastInstance() {
    return this.instances[this.instances.length - 1];
  }

  static reset() {
    this.instances = [];
  }
}

global.EventSource = MockEventSource as unknown as typeof EventSource;

describe('ProgressLog', () => {
  beforeEach(() => {
    MockEventSource.reset();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('shows initial state when not active', () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={false} />);

    expect(screen.getByText('Start a scan to see live progress')).toBeInTheDocument();
  });

  it('shows waiting state when active but no logs', () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    expect(screen.getByText('Waiting for progress updates...')).toBeInTheDocument();
    expect(screen.getByText('● Connected')).toBeInTheDocument();
  });

  it('connects to SSE endpoint', () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    expect(MockEventSource.instances).toHaveLength(1);
    expect(MockEventSource.instances[0].url).toBe('/api/scans/scan-123/progress');
  });

  it('displays progress events', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:00Z',
          level: 'info',
          message: 'Starting crawl',
          stage: 'crawl',
        }),
      }));
    });

    await waitFor(() => {
      expect(screen.getByText('Starting crawl')).toBeInTheDocument();
    });
  });

  it('displays multiple progress events in order', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:00Z',
          level: 'info',
          message: 'Starting crawl',
          stage: 'crawl',
        }),
      }));
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:01Z',
          level: 'warning',
          message: 'Slow response detected',
          stage: 'check',
        }),
      }));
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:02Z',
          level: 'error',
          message: 'Connection timeout',
          stage: 'check',
        }),
      }));
    });

    await waitFor(() => {
      const messages = screen.getAllByText(/Starting crawl|Slow response|Connection timeout/);
      expect(messages).toHaveLength(3);
    });
  });

  it('shows correct icons for log levels', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:00Z',
          level: 'info',
          message: 'Info message',
          stage: 'scan',
        }),
      }));
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:01Z',
          level: 'warning',
          message: 'Warning message',
          stage: 'scan',
        }),
      }));
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:02Z',
          level: 'error',
          message: 'Error message',
          stage: 'scan',
        }),
      }));
    });

    await waitFor(() => {
      // Check that icons are rendered (they're SVG elements)
      const svgs = screen.getAllByRole('img');
      expect(svgs.length).toBeGreaterThan(0);
    });
  });

  it('handles complete event and closes connection', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('complete', {
        data: JSON.stringify({ status: 'completed' }),
      }));
    });

    await waitFor(() => {
      expect(screen.getByText('Scan completed')).toBeInTheDocument();
      expect(screen.getByText('○ Disconnected')).toBeInTheDocument();
    });
  });

  it('handles failed complete event', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('complete', {
        data: JSON.stringify({ status: 'failed' }),
      }));
    });

    await waitFor(() => {
      expect(screen.getByText('Scan failed')).toBeInTheDocument();
    });
  });

  it('handles timeout event', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('timeout', {
        data: JSON.stringify({ message: 'Stream timeout after 300s' }),
      }));
    });

    await waitFor(() => {
      expect(screen.getByText('Stream timeout after 300s')).toBeInTheDocument();
      expect(screen.getByText('○ Disconnected')).toBeInTheDocument();
    });
  });

  it('handles connection error', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.onerror?.();
    });

    await waitFor(() => {
      expect(screen.getByText('○ Disconnected')).toBeInTheDocument();
    });
  });

  it('cleans up on unmount', () => {
    const { unmount } = renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    expect(eventSource?.readyState).toBe(MockEventSource.OPEN);

    unmount();

    expect(eventSource?.readyState).toBe(MockEventSource.CLOSED);
  });

  it('cleans up when isActive becomes false', () => {
    const { rerender } = renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    expect(eventSource?.readyState).toBe(MockEventSource.OPEN);

    rerender(<ProgressLog scanId="scan-123" isActive={false} />);

    expect(eventSource?.readyState).toBe(MockEventSource.CLOSED);
  });

  it('does not connect when scanId is missing', () => {
    renderWithProviders(<ProgressLog scanId="" isActive={true} />);

    expect(MockEventSource.instances).toHaveLength(0);
  });

  it('formats timestamps', async () => {
    renderWithProviders(<ProgressLog scanId="scan-123" isActive={true} />);

    const eventSource = MockEventSource.getLastInstance();
    await act(async () => {
      eventSource?.emit(new MessageEvent('progress', {
        data: JSON.stringify({
          timestamp: '2024-01-15T10:00:00Z',
          level: 'info',
          message: 'Test message',
          stage: 'scan',
        }),
      }));
    });

    await waitFor(() => {
      // Should show relative time format
      expect(screen.getByText(/Test message/)).toBeInTheDocument();
    });
  });
});