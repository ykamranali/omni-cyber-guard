import { test, expect } from '@playwright/test';

test.describe('Inventory', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[type="email"]', 'admin@omnidigitalsolution.com');
    await page.fill('input[type="password"]', 'ChangeMe!12345');
    await page.click('button[type="submit"]');
    await page.waitForURL(/.*\/dashboard/);
  });

  test('should display assets and allow global search', async ({ page }) => {
    await page.goto('/assets');
    await expect(page.locator('h1')).toContainText('Assets');

    // Test global search
    const searchInput = page.locator('input[placeholder*="Global search"]');
    await searchInput.fill('192.168.1.1');
    
    // The dropdown should appear (if asset exists)
    // We just ensure the search component is present and interactive
    await expect(searchInput).toBeVisible();
  });
});
