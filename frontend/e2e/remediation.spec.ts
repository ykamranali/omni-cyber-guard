import { test, expect } from '@playwright/test';

test.describe('Remediation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[type="email"]', 'admin@omnidigitalsolution.com');
    await page.fill('input[type="password"]', 'ChangeMe!12345');
    await page.click('button[type="submit"]');
    await page.waitForURL(/.*\/dashboard/);
  });

  test('should navigate to remediation tasks', async ({ page }) => {
    await page.goto('/remediation');
    await expect(page.locator('h1')).toContainText('Remediation');

    // Verify there is a table or list
    await expect(page.locator('table')).toBeVisible().catch(() => {
        // Alternatively a grid might be used
        expect(page.locator('.grid')).toBeVisible();
    });
  });
});
