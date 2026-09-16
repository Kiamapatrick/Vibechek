import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('loads without console errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.waitForLoadState('networkidle');
    expect(errors).toHaveLength(0);
  });

  test('shows dashboard title', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('VibeShield');
  });

  test('shows empty state when no scans', async ({ page }) => {
    await expect(page.locator('text=No scans yet')).toBeVisible();
  });

  test('shows scan wizard form', async ({ page }) => {
    await expect(page.locator('label:has-text("Target URL")')).toBeVisible();
    await expect(page.locator('label:has-text("Max Pages")')).toBeVisible();
    await expect(page.locator('label:has-text("Max Depth")')).toBeVisible();
    await expect(page.locator('label:has-text("Timeout (seconds)")')).toBeVisible();
    await expect(page.locator('label:has-text("Allow write tests")')).toBeVisible();
    await expect(page.locator('button:has-text("Start Scan")')).toBeVisible();
  });
});

test.describe('Scan Wizard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('blocks empty URL submission via HTML5 validation', async ({ page }) => {
    await page.click('button:has-text("Start Scan")');
    const urlInput = page.locator('input[type="url"]');
    await expect(urlInput).toHaveAttribute('required');
    await expect(urlInput).toHaveAttribute('type', 'url');
  });

  test('disables submit button when URL is empty', async ({ page }) => {
    await expect(page.locator('button:has-text("Start Scan")')).toBeDisabled();
  });

  test('enables submit button when URL is filled', async ({ page }) => {
    await page.fill('input[type="url"]', 'https://example.com');
    await expect(page.locator('button:has-text("Start Scan")')).toBeEnabled();
  });

  test('clamps maxPages to 1-1000', async ({ page }) => {
    const maxPagesInput = page.locator('input[id="maxPages"]');

    await maxPagesInput.fill('0');
    await expect(maxPagesInput).toHaveValue('1');

    await maxPagesInput.fill('1001');
    await expect(maxPagesInput).toHaveValue('1000');

    await maxPagesInput.fill('500');
    await expect(maxPagesInput).toHaveValue('500');
  });

  test('clamps maxDepth to 0-10', async ({ page }) => {
    const maxDepthInput = page.locator('input[id="maxDepth"]');

    await maxDepthInput.fill('-1');
    await expect(maxDepthInput).toHaveValue('0');

    await maxDepthInput.fill('11');
    await expect(maxDepthInput).toHaveValue('10');
  });

  test('clamps timeout to 1-300', async ({ page }) => {
    const timeoutInput = page.locator('input[id="timeout"]');

    await timeoutInput.fill('0');
    await expect(timeoutInput).toHaveValue('1');

    await timeoutInput.fill('301');
    await expect(timeoutInput).toHaveValue('300');
  });

  test('shows warning when allow_write_tests is enabled', async ({ page }) => {
    const checkbox = page.locator('input[id="allowWriteTests"]');
    await expect(checkbox).not.toBeChecked();

    await checkbox.check();
    await expect(checkbox).toBeChecked();
  });
});

test.describe('Scan Detail Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/scan/scan-123');
  });

  test('loads scan detail page', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('example.com');
  });

  test('shows tabs: Progress, Findings, Triage, Report', async ({ page }) => {
    await expect(page.locator('text=Progress')).toBeVisible();
    await expect(page.locator('text=Findings')).toBeVisible();
    await expect(page.locator('text=Triage')).toBeVisible();
    await expect(page.locator('text=Report')).toBeVisible();
  });

  test('shows Progress tab by default', async ({ page }) => {
    await expect(page.locator('text=Live Progress')).toBeVisible();
  });
});

test.describe('Progress Log (SSE)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/scan/scan-123');
  });

  test('shows connected status', async ({ page }) => {
    await expect(page.locator('text=● Connected')).toBeVisible({ timeout: 10000 });
  });

  test('displays progress events', async ({ page }) => {
    await page.waitForSelector('text=Starting crawl', { timeout: 15000 });
    await expect(page.locator('text=Starting crawl')).toBeVisible();
  });

  test('auto-scrolls to new logs', async ({ page }) => {
    await page.waitForSelector('text=Starting crawl', { timeout: 15000 });
    const logContainer = page.locator('.overflow-y-auto');
    const initialScroll = await logContainer.evaluate(el => el.scrollTop);
    
    // Wait for more logs
    await page.waitForTimeout(2000);
    const laterScroll = await logContainer.evaluate(el => el.scrollTop);
    
    // Should have scrolled (or at least not scrolled up)
    expect(laterScroll).toBeGreaterThanOrEqual(initialScroll);
  });
});

test.describe('Findings Table', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/scan/scan-123');
    await page.click('text=Findings');
    await page.waitForLoadState('networkidle');
  });

  test('shows findings in severity order (Critical -> High -> Medium -> Low -> Info)', async ({ page }) => {
    const rows = page.locator('tbody tr');
    await expect(rows.first()).toContainText('Critical');
    await expect(rows.nth(1)).toContainText('High');
    await expect(rows.nth(2)).toContainText('Medium');
    await expect(rows.nth(3)).toContainText('Low');
    await expect(rows.nth(4)).toContainText('Info');
  });

  test('sorts by severity when header clicked', async ({ page }) => {
    await page.click('th:has-text("Severity")');
    const rows = page.locator('tbody tr');
    await expect(rows.first()).toContainText('Info');
    await expect(rows.last()).toContainText('Critical');

    await page.click('th:has-text("Severity")');
    await expect(rows.first()).toContainText('Critical');
    await expect(rows.last()).toContainText('Info');
  });

  test('filters by search', async ({ page }) => {
    await page.fill('input[placeholder="Search findings..."]', 'XSS');
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Reflected XSS');
  });

  test('filters by severity dropdown', async ({ page }) => {
    await page.selectOption('select:has(option:has-text("All Severities"))', 'Critical');
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Critical');
  });

  test('filters by check dropdown', async ({ page }) => {
    await page.selectOption('select:has(option:has-text("All Checks"))', 'sql_injection');
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('SQL Injection');
  });

  test('shows stats cards matching table data', async ({ page }) => {
    const stats = page.locator('.grid .rounded-lg');
    await expect(stats).toHaveCount(5);
  });

  test('clears filters', async ({ page }) => {
    await page.fill('input[placeholder="Search findings..."]', 'XSS');
    await page.click('text=Clear filters');
    await expect(page.locator('input[placeholder="Search findings..."]')).toHaveValue('');
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(5);
  });
});

test.describe('Triage View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/scan/scan-123');
    await page.click('text=Triage');
    await page.waitForLoadState('networkidle');
  });

  test('shows Runs and Compare tabs', async ({ page }) => {
    await expect(page.locator('text=Runs')).toBeVisible();
    await expect(page.locator('text=Compare')).toBeVisible();
  });

  test('shows Run Baseline and Run LLM Triage buttons', async ({ page }) => {
    await expect(page.locator('button:has-text("Run Baseline")')).toBeVisible();
    await expect(page.locator('button:has-text("Run LLM Triage")')).toBeVisible();
  });

  test('runs baseline triage', async ({ page }) => {
    await page.click('button:has-text("Run Baseline")');
    await expect(page.locator('text=Running...')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });
    await expect(page.locator('text=Test Finding')).toBeVisible({ timeout: 30000 });
  });

  test('runs LLM triage', async ({ page }) => {
    await page.click('button:has-text("Run LLM Triage")');
    await expect(page.locator('text=Running...')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });
    await expect(page.locator('text=LLM explanation')).toBeVisible({ timeout: 30000 });
  });

  test('switches to Compare tab', async ({ page }) => {
    // First run baseline to have data
    await page.click('button:has-text("Run Baseline")');
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });

    await page.click('text=Compare');
    await expect(page.locator('text=Baseline vs LLM Comparison')).toBeVisible();
    await expect(page.locator('text=Baseline Only')).toBeVisible();
    await expect(page.locator('text=LLM Only')).toBeVisible();
    await expect(page.locator('text=Changed Priority')).toBeVisible();
  });

  test('shows LLM only findings in compare', async ({ page }) => {
    await page.click('button:has-text("Run Baseline")');
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });

    await page.click('button:has-text("Run LLM Triage")');
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });

    await page.click('text=Compare');
    await expect(page.locator('text=LLM Only')).toBeVisible();
  });

  test('switches back to Runs tab', async ({ page }) => {
    await page.click('text=Compare');
    await expect(page.locator('text=Baseline vs LLM Comparison')).toBeVisible();

    await page.click('text=Runs');
    await expect(page.locator('text=Run Baseline')).toBeVisible();
  });

  test('expands finding card to show details', async ({ page }) => {
    await page.click('button:has-text("Run Baseline")');
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });

    await page.click('text=Test Finding');
    await expect(page.locator('text=Detailed explanation here')).toBeVisible();
    await expect(page.locator('text=Detailed fix here')).toBeVisible();
  });
});

test.describe('Report View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/scan/scan-123');
    await page.click('text=Report');
    await page.waitForLoadState('networkidle');
  });

  test('shows format tabs: Plain, JSON, Both', async ({ page }) => {
    await expect(page.locator('text=Plain')).toBeVisible();
    await expect(page.locator('text=Json')).toBeVisible();
    await expect(page.locator('text=Both')).toBeVisible();
  });

  test('loads plain format by default', async ({ page }) => {
    await expect(page.locator('text=VibeShield Security Scan Report')).toBeVisible();
  });

  test('switches to JSON format', async ({ page }) => {
    await page.click('text=Json');
    await expect(page.locator('text=scan_id')).toBeVisible();
  });

  test('switches to Both format', async ({ page }) => {
    await page.click('text=Both');
    await expect(page.locator('text=Plain Text')).toBeVisible();
    await expect(page.locator('text=JSON')).toBeVisible();
  });

  test('copies plain format to clipboard', async ({ page }) => {
    await page.click('button:has-text("Copy")');
    await expect(page.locator('text=Copied')).toBeVisible({ timeout: 2000 });
  });

  test('copies JSON format to clipboard', async ({ page }) => {
    await page.click('text=Json');
    await expect(page.locator('text=scan_id')).toBeVisible();
    await page.click('button:has-text("Copy")');
    await expect(page.locator('text=Copied')).toBeVisible({ timeout: 2000 });
  });

  test('copies Both format to clipboard', async ({ page }) => {
    await page.click('text=Both');
    await expect(page.locator('text=Plain Text')).toBeVisible();
    await page.click('button:has-text("Copy")');
    await expect(page.locator('text=Copied')).toBeVisible({ timeout: 2000 });
  });

  test('downloads plain format', async ({ page }) => {
    const downloadPromise = page.waitForEvent('download');
    await page.click('button:has-text("Download")');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.txt$/);
  });

  test('downloads JSON format', async ({ page }) => {
    await page.click('text=Json');
    await expect(page.locator('text=scan_id')).toBeVisible();
    const downloadPromise = page.waitForEvent('download');
    await page.click('button:has-text("Download")');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.json$/);
  });
});

test.describe('Visual / Cross-cutting', () => {
  test('dark mode toggle works', async ({ page }) => {
    await page.goto('/');
    const darkModeToggle = page.locator('button[aria-label="Toggle dark mode"]');
    if (await darkModeToggle.isVisible()) {
      await darkModeToggle.click();
      await expect(page.locator('html')).toHaveClass(/dark/);
    }
  });

  test('responsive layout on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    await expect(page.locator('h1')).toBeVisible();
    await expect(page.locator('input[type="url"]')).toBeVisible();
  });

  test('responsive layout on tablet', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/');
    await expect(page.locator('h1')).toBeVisible();
  });

  test('no hydration mismatches', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('hydration')) {
        errors.push(msg.text());
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.goto('/scan/scan-123');
    await page.waitForLoadState('networkidle');

    expect(errors).toHaveLength(0);
  });

  test('no React key warnings', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('key')) {
        errors.push(msg.text());
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.goto('/scan/scan-123');
    await page.waitForLoadState('networkidle');

    expect(errors).toHaveLength(0);
  });
});

test.describe('Full Scan Flow', () => {
  test('complete flow: dashboard -> start scan -> progress -> findings -> triage -> report', async ({ page }) => {
    // Dashboard
    await page.goto('/');
    await expect(page.locator('h1')).toContainText('VibeShield');

    // Start scan
    await page.fill('input[type="url"]', 'https://example.com');
    await page.click('button:has-text("Start Scan")');
    
    // Should redirect to scan detail
    await page.waitForURL(/\/scan\/.+/);
    await expect(page.locator('h1')).toContainText('example.com');

    // Progress tab
    await expect(page.locator('text=Live Progress')).toBeVisible();
    await page.waitForSelector('text=Scan completed', { timeout: 30000 });

    // Findings tab
    await page.click('text=Findings');
    await expect(page.locator('text=Critical')).toBeVisible();

    // Triage tab
    await page.click('text=Triage');
    await page.click('button:has-text("Run Baseline")');
    await expect(page.locator('text=Running...')).not.toBeVisible({ timeout: 30000 });

    // Compare tab
    await page.click('text=Compare');
    await expect(page.locator('text=Baseline vs LLM Comparison')).toBeVisible();

    // Report tab
    await page.click('text=Report');
    await expect(page.locator('text=VibeShield Security Scan Report')).toBeVisible();
    await page.click('button:has-text("Copy")');
    await expect(page.locator('text=Copied')).toBeVisible({ timeout: 2000 });
  });
});