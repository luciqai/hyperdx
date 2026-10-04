import { TeamPage } from '../page-objects/TeamPage';
import { expect, test } from '../utils/base-test';

test.describe('RBAC roles', { tag: ['@rbac', '@full-stack'] }, () => {
  let teamPage: TeamPage;

  test.beforeEach(async ({ page }) => {
    teamPage = new TeamPage(page);
    await teamPage.goto();
    await teamPage.openAccessTab();
  });

  test('seeds the three built-in roles', { tag: '@full-stack' }, async () => {
    await expect(teamPage.rbacRoles).toBeVisible();

    for (const name of ['Admin', 'Member', 'ReadOnly']) {
      await expect(teamPage.getRoleRow(name).first()).toBeVisible();
    }

    // System roles are read-only: they offer View, never Edit/Delete.
    const adminRow = teamPage.getRoleRow('Admin').first();
    await expect(adminRow.getByText('System')).toBeVisible();
    await expect(adminRow.getByRole('button', { name: 'View' })).toBeVisible();
    await expect(adminRow.getByRole('button', { name: 'Delete' })).toHaveCount(
      0,
    );
  });

  test(
    'an admin can create a custom role',
    { tag: '@full-stack' },
    async ({ page }) => {
      const roleName = `E2E On-call ${Date.now()}`;

      await teamPage.addRoleButton.click();
      await expect(teamPage.roleEditorModal).toBeVisible();

      await teamPage.roleEditorModal.getByLabel('Role name').fill(roleName);

      // Grant alerts:manage — the matrix labels each radio `<resource>-<level>`.
      await teamPage.roleEditorModal
        .getByRole('radio', { name: 'alerts-manage' })
        .click();

      await page.getByRole('button', { name: 'Create role' }).click();

      await expect(teamPage.roleEditorModal).toBeHidden();
      await expect(teamPage.getRoleRow(roleName).first()).toBeVisible();
    },
  );

  test(
    'a system role opens read-only and offers duplication',
    { tag: '@full-stack' },
    async () => {
      await teamPage
        .getRoleRow('Member')
        .first()
        .getByRole('button', { name: 'View' })
        .click();

      await expect(teamPage.roleEditorModal).toBeVisible();
      await expect(
        teamPage.roleEditorModal.getByLabel('Role name'),
      ).toBeDisabled();
      await expect(
        teamPage.roleEditorModal.getByRole('button', {
          name: 'Duplicate as custom role',
        }),
      ).toBeVisible();
    },
  );
});
