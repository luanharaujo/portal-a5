// Minimal WebAuthn (passkeys) for ES256 only, which is what Apple and most platform
// authenticators use. Registration trusts the SPKI the browser exposes through
// AuthenticatorAttestationResponse.getPublicKey() (attestation "none"); the session that
// registers is already trusted, so there is no attestation chain to check.

export function b64url(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ''
  for (const x of b) s += String.fromCharCode(x)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromB64url(s: string): Uint8Array {
  const t = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

export class WebAuthnError extends Error {}

interface ClientData { type: string; challenge: string; origin: string; crossOrigin?: boolean }

function parseClientData(b64: string): { raw: Uint8Array; data: ClientData } {
  const raw = fromB64url(b64)
  let data: ClientData
  try {
    data = JSON.parse(new TextDecoder().decode(raw))
  } catch {
    throw new WebAuthnError('bad clientDataJSON')
  }
  return { raw, data }
}

async function checkAuthData(authData: Uint8Array, rpId: string): Promise<number> {
  if (authData.length < 37) throw new WebAuthnError('authenticatorData too short')
  const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)))
  for (let i = 0; i < 32; i++) if (authData[i] !== rpHash[i]) throw new WebAuthnError('rpId mismatch')
  const flags = authData[32]
  if (!(flags & 0x01)) throw new WebAuthnError('user not present')
  if (!(flags & 0x04)) throw new WebAuthnError('user not verified')
  return new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0)
}

function checkClientData(d: ClientData, type: string, challenge: string, origin: string) {
  if (d.type !== type) throw new WebAuthnError('wrong type')
  if (d.challenge !== challenge) throw new WebAuthnError('wrong challenge')
  if (d.origin !== origin) throw new WebAuthnError('wrong origin')
  if (d.crossOrigin) throw new WebAuthnError('crossOrigin')
}

export interface Registration { credentialId: string; publicKey: string; signCount: number }

export async function verifyRegistration(
  input: { id: string; clientDataJSON: string; authenticatorData: string; publicKey: string; publicKeyAlgorithm: number },
  expected: { challenge: string; origin: string; rpId: string },
): Promise<Registration> {
  if (input.publicKeyAlgorithm !== -7) throw new WebAuthnError('only ES256 is supported')
  const { data } = parseClientData(input.clientDataJSON)
  checkClientData(data, 'webauthn.create', expected.challenge, expected.origin)
  const authData = fromB64url(input.authenticatorData)
  const signCount = await checkAuthData(authData, expected.rpId)
  if (!(authData[32] & 0x40)) throw new WebAuthnError('no attested credential in authenticatorData')
  // attested credential data: aaguid(16) | idLen(2) | id
  const idLen = new DataView(authData.buffer, authData.byteOffset + 53, 2).getUint16(0)
  const credId = b64url(authData.slice(55, 55 + idLen))
  if (credId !== input.id) throw new WebAuthnError('credential id mismatch')
  // the key must import as a P-256 public key
  await crypto.subtle.importKey('spki', fromB64url(input.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  return { credentialId: credId, publicKey: input.publicKey, signCount }
}

// ECDSA signatures from authenticators are DER; WebCrypto wants raw r||s.
function derToRaw(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new WebAuthnError('bad signature encoding')
  let i = 2
  if (der[1] & 0x80) i = 2 + (der[1] & 0x7f)
  const part = () => {
    if (der[i] !== 0x02) throw new WebAuthnError('bad signature encoding')
    const len = der[i + 1]
    let v = der.slice(i + 2, i + 2 + len)
    i += 2 + len
    while (v.length > 32 && v[0] === 0) v = v.slice(1)
    if (v.length > 32) throw new WebAuthnError('bad signature encoding')
    const out = new Uint8Array(32)
    out.set(v, 32 - v.length)
    return out
  }
  const r = part()
  const s = part()
  const raw = new Uint8Array(64)
  raw.set(r)
  raw.set(s, 32)
  return raw
}

export async function verifyAssertion(
  input: { clientDataJSON: string; authenticatorData: string; signature: string },
  key: { publicKey: string; signCount: number },
  expected: { challenge: string; origin: string; rpId: string },
): Promise<number> {
  const { raw, data } = parseClientData(input.clientDataJSON)
  checkClientData(data, 'webauthn.get', expected.challenge, expected.origin)
  const authData = fromB64url(input.authenticatorData)
  const signCount = await checkAuthData(authData, expected.rpId)
  const k = await crypto.subtle.importKey('spki', fromB64url(key.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  const cdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', raw))
  const signed = new Uint8Array(authData.length + 32)
  signed.set(authData)
  signed.set(cdHash, authData.length)
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, derToRaw(fromB64url(input.signature)), signed)
  if (!ok) throw new WebAuthnError('signature mismatch')
  // counters: Apple passkeys always report 0; a non-zero counter must grow
  if (signCount !== 0 || key.signCount !== 0) {
    if (signCount <= key.signCount) throw new WebAuthnError('sign counter went back (cloned key?)')
  }
  return signCount
}
