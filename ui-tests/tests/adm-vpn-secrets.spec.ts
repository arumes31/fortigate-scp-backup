import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { inflateRawSync } from 'node:zlib';

import { expect, test } from './quality-fixture';

const fixtureOrigin = 'http://127.0.0.1:18901';
const storedSecrets = [
  'SENTINEL-STORED-RO-PSK-5e19',
  'SENTINEL-STORED-HCI-PSK-83d1',
];

function zipContents(path: string): Buffer {
  const archive = readFileSync(path);
  const endSignature = 0x06054b50;
  let endOffset = -1;
  for (let offset = archive.length - 22; offset >= Math.max(0, archive.length - 65_557); offset -= 1) {
    if (archive.readUInt32LE(offset) === endSignature) {
      endOffset = offset;
      break;
    }
  }
  if (endOffset < 0) throw new Error('trace ZIP end record not found');

  const entryCount = archive.readUInt16LE(endOffset + 10);
  let centralOffset = archive.readUInt32LE(endOffset + 16);
  const contents: Buffer[] = [];
  for (let entry = 0; entry < entryCount; entry += 1) {
    if (archive.readUInt32LE(centralOffset) !== 0x02014b50) throw new Error('invalid trace ZIP directory');
    const method = archive.readUInt16LE(centralOffset + 10);
    const compressedSize = archive.readUInt32LE(centralOffset + 20);
    const nameLength = archive.readUInt16LE(centralOffset + 28);
    const extraLength = archive.readUInt16LE(centralOffset + 30);
    const commentLength = archive.readUInt16LE(centralOffset + 32);
    const localOffset = archive.readUInt32LE(centralOffset + 42);
    if (archive.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('invalid trace ZIP entry');
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = archive.subarray(dataOffset, dataOffset + compressedSize);
    if (method === 0) contents.push(compressed);
    else if (method === 8) contents.push(inflateRawSync(compressed));
    else throw new Error(`unsupported trace ZIP compression method ${method}`);
    centralOffset += 46 + nameLength + extraLength + commentLength;
  }
  return Buffer.concat(contents);
}

test('ADM VPN edit never returns stored PSKs to the browser or trace', async ({ page }, testInfo) => {
  const viewport = testInfo.project.use.viewport as { width: number; height: number };
  const responseBodies: Promise<string>[] = [];
  const consoleMessages: string[] = [];
  page.on('console', message => consoleMessages.push(message.text()));
  page.on('response', response => {
    if (response.url().startsWith(fixtureOrigin)) {
      responseBodies.push(response.text().catch(() => ''));
    }
  });

  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Details for edge.example.test' }).click();
  await page.locator('#vpn-detail-7').getByRole('button', { name: 'Edit edge.example.test' }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit configuration' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('IPsec PSK RO')).toHaveAttribute('type', 'password');
  await expect(dialog.getByLabel('IPsec PSK HCI')).toHaveAttribute('type', 'password');
  await expect(dialog.getByLabel('IPsec PSK RO')).toHaveValue('');
  await expect(dialog.getByLabel('IPsec PSK HCI')).toHaveValue('');
  await expect(dialog).toContainText('Leave blank to keep the current secret.');
  await page.screenshot({
    path: testInfo.outputPath('adm-vpn-secret-safe-edit.png'),
    animations: 'disabled',
  });

  const dom = await page.locator('html').evaluate(element => element.outerHTML);
  const bodies = (await Promise.all(responseBodies)).join('\n');
  const browserEvidence = [dom, bodies, consoleMessages.join('\n')].join('\n');
  for (const secret of storedSecrets) {
    expect(browserEvidence, `stored PSK leaked into browser-visible evidence: ${secret}`).not.toContain(secret);
  }

  const tracePath = testInfo.outputPath('adm-vpn-secret-audit.zip');
  const traceHelper = resolve(__dirname, '../helpers/trace-adm-vpn-secret-audit.mjs');
  execFileSync(process.execPath, [
    traceHelper, fixtureOrigin, tracePath,
    String(viewport.width), String(viewport.height),
  ], { stdio: 'pipe', timeout: 60_000 });
  const traceEvidence = zipContents(tracePath).toString('utf8');
  for (const secret of storedSecrets) {
    expect(traceEvidence, `stored PSK leaked into Playwright trace: ${secret}`).not.toContain(secret);
  }
});
