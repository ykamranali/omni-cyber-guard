import { test, expect } from '@playwright/test';

test.describe('Agent Security Engineer', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[type="email"]', 'admin@omnidigitalsolution.com');
    await page.fill('input[type="password"]', 'ChangeMe!12345');
    await page.click('button[type="submit"]');
    await page.waitForURL(/.*\/dashboard/);
  });

  test('should open agent chat and allow asking a question', async ({ page }) => {
    await page.goto('/ask-agent');
    await expect(page.locator('h1')).toContainText('Security Engineer');

    const chatInput = page.locator('textarea[placeholder*="Ask the engineer"]');
    if (await chatInput.isVisible()) {
      await chatInput.fill('What is my most critical finding?');
      await page.click('button[title="Send message"]');
      
      // Wait for a response bubble
      const lastMessage = page.locator('.prose').last();
      await expect(lastMessage).toBeVisible({ timeout: 15000 });
    }
  });
});
