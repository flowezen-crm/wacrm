
import 'server-only'
import crypto from 'node:crypto'

/**
 * Verify Meta's HMAC-SHA256 signature on the exact raw webhook request body.
 *
 * Server-only module. Never expose META_APP_SECRET through NEXT_PUBLIC_.
 * Multiple app secrets can be configured using comma-separated values.
 */

export function parseAppSecrets(raw: string | undefined): string[] {
  if (!raw) return []

  return raw
    .split(',')
    .map((secret) => secret.trim())
    .filter((secret) => secret.length > 0)
}

function signatureMatches(
  rawBody: string,
  signatureHeader: string,
  secret: string,
): boolean {
  const expected =
    'sha256=' +
    crypto.createHmac('sha256', secret).update(rawBody).digest('hex')

  const actualBuffer = Buffer.from(signatureHeader, 'utf8')
  const expectedBuffer = Buffer.from(expected, 'utf8')

  if (actualBuffer.length !== expectedBuffer.length) return false

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer)
}

export function verifyMetaWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
): boolean {
  // Read secret at runtime, not through direct dot notation.
  const secrets = parseAppSecrets(process.env['META_APP_SECRET'])

  if (secrets.length === 0) {
    console.error(
      '[webhook] META_APP_SECRET is not configured; rejecting webhook request.',
    )
    return false
  }

  if (
    !signatureHeader ||
    !/^sha256=[0-9a-f]{64}$/i.test(signatureHeader)
  ) {
    return false
  }

  let matched = false

  for (const secret of secrets) {
    if (signatureMatches(rawBody, signatureHeader, secret)) {
      matched = true
    }
  }

  return matched
}

export function verifyTokenMatches(
  stored: string,
  presented: string,
): boolean {
  const storedHash = crypto.createHash('sha256').update(stored).digest()
  const presentedHash = crypto
    .createHash('sha256')
    .update(presented)
    .digest()

  return crypto.timingSafeEqual(storedHash, presentedHash)
}
