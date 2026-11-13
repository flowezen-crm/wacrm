import crypto from 'node:crypto'

/**
 * Verify Meta's HMAC-SHA256 signature on the exact raw webhook request body.
 *
 * META_APP_SECRET is read only on the server at request time. Never expose it
 * through a NEXT_PUBLIC_ variable or import this module into client components.
 *
 * Multiple app secrets may be configured as a comma-separated environment
 * variable. A signature is accepted if it matches any configured secret.
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
  const secrets = parseAppSecrets(process.env.META_APP_SECRET)

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

  // Check every configured secret rather than returning on the first match.
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
