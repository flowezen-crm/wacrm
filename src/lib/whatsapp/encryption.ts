
import 'server-only'
import crypto from 'node:crypto'

/**
 * WhatsApp token encryption.
 *
 * Server-only module.
 * Never import into Client Components or browser utilities.
 *
 * New encryption: AES-256-GCM
 * Legacy decryption: AES-256-CBC
 */

function getEncryptionKey(): Buffer {
  // Read secret at runtime. Never expose through NEXT_PUBLIC_.
  const rawKey = process.env['ENCRYPTION_KEY']

  if (!rawKey || !/^[0-9a-fA-F]{64}$/.test(rawKey)) {
    throw new Error(
      'ENCRYPTION_KEY must be configured as exactly 64 hexadecimal characters (32 bytes).',
    )
  }

  return Buffer.from(rawKey, 'hex')
}

const GCM_IV_LENGTH = 12
const CBC_IV_LENGTH = 16
const AUTH_TAG_LENGTH = 16

/**
 * Encrypt using AES-256-GCM.
 */
export function encrypt(text: string): string {
  const key = getEncryptionKey()
  const iv = crypto.randomBytes(GCM_IV_LENGTH)

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv,
  )

  let encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  const authTag = cipher.getAuthTag()

  return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`
}

/**
 * Decrypt GCM or legacy CBC encrypted tokens.
 */
export function decrypt(encryptedText: string): string {
  const key = getEncryptionKey()
  const parts = encryptedText.split(':')

  if (parts.length === 3) {
    // Current AES-256-GCM format.
    const [ivHex, ctHex, tagHex] = parts

    const iv = Buffer.from(ivHex, 'hex')
    const authTag = Buffer.from(tagHex, 'hex')

    if (iv.length !== GCM_IV_LENGTH) {
      throw new Error('Invalid GCM IV length.')
    }

    if (authTag.length !== AUTH_TAG_LENGTH) {
      throw new Error('Invalid GCM authentication tag length.')
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      iv,
    )

    decipher.setAuthTag(authTag)

    let decrypted = decipher.update(ctHex, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
  }

  if (parts.length === 2) {
    // Legacy AES-256-CBC format.
    const [ivHex, ctHex] = parts

    const iv = Buffer.from(ivHex, 'hex')

    if (iv.length !== CBC_IV_LENGTH) {
      throw new Error('Invalid CBC IV length.')
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      key,
      iv,
    )

    let decrypted = decipher.update(ctHex, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
  }

  throw new Error(
    `Unrecognised encrypted token format. Expected 1 or 2 colons, got ${parts.length - 1}.`,
  )
}

/**
 * Detect legacy CBC format.
 */
export function isLegacyFormat(encryptedText: string): boolean {
  return encryptedText.split(':').length === 2
}
