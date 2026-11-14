
import 'server-only'
import crypto from 'node:crypto'

/**
 * Verify Meta's HMAC-SHA256 signature on the exact raw webhook request body.
 *
 * Server-only module.
 * Never expose META_APP_SECRET through NEXT_PUBLIC_.
 *
 * Multiple app secrets can be configured using comma-separated values.
 * A request is accepted if its signature matches any configured secret.
 */

/**
 * Parse comma-separated Meta App Secrets.
 * Trims whitespace and removes empty entries.
 */
export function parseAppSecrets(raw: string | undefined): string[] {
  if (!raw) return []

  return raw
    .split(',')
    .map((secret) => secret.trim())
    .filter((secret) => secret.length > 0)
}

/**
 * Compare webhook signatures using constant-time comparison.
 */
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

  if (actualBuffer.length !== expectedBuffer.length) {
    return false
  }

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer)
}

/**
 * Verify Meta webhook signature.
 */
export function verifyMetaWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
): boolean {
  // Read secret at runtime.
  const secrets = parseAppSecrets(process.env['META_APP_SECRET'])

  // Fail closed if no secret is configured.
  if (secrets.length === 0) {
    console.error(
      '[webhook] META_APP_SECRET is not configured; rejecting webhook request.',
    )
    return false
  }

  // Meta sends: sha256=<64-character hexadecimal HMAC>.
  if (
    !signatureHeader ||
    !/^sha256=[0-9a-f]{64}$/.test(signatureHeader)
  ) {
    return false
  }

  // Check every configured secret.
  let matched = false

  for (const secret of secrets) {
    if (signatureMatches(rawBody, signatureHeader, secret)) {
      matched = true
    }
  }

  return matched
}

/**
 * Compare webhook verification tokens safely.
 */
export function verifyTokenMatches(
  stored: string,
  presented: string,
): boolean {
  const storedHash = crypto
    .createHash('sha256')
    .update(stored)
    .digest()

  const presentedHash = crypto
    .createHash('sha256')
    .update(presented)
    .digest()

  return crypto.timingSafeEqual(storedHash, presentedHash)
}
