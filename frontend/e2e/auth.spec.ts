import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test('should allow a valid user to log in', async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[type="email"]', 'admin@omnidigitalsolution.com');
    await page.fill('input[type="password"]', 'ChangeMe!12345');
    await page.click('button[type="submit"]');

    // Expect to be redirected to the dashboard
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('h1')).toContainText('Dashboard');
  });

  test('should display an error on invalid login', async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[type="email"]', 'wrong@user.com');
    await page.fill('input[type="password"]', 'incorrect');
    await page.click('button[type="submit"]');

    // Expect an error message
    const errorMsg = page.locator('.text-critical');
    await expect(errorMsg).toBeVisible();
    await expect(errorMsg).toContainText('Incorrect email or password');
  });
});
