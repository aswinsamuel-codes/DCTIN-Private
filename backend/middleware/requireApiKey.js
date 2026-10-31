import { timingSafeEqual } from 'crypto';

/**
 * Protect write endpoints with a shared admin API key
 * Clients send the key in the X-API-Key header
 * Fails closed: if ADMIN_API_KEY is not configured, all protected requests are rejected
 */
export function requireApiKey(req, res, next) {
  const expected = process.env.ADMIN_API_KEY;

  if (!expected) {
    return res.status(503).json({
      success: false,
      error: 'Service Unavailable',
      message: 'ADMIN_API_KEY is not configured on the server; write endpoints are disabled'
    });
  }

  const provided = req.get('X-API-Key') || '';
  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(provided);

  // Length check first: timingSafeEqual throws on unequal lengths
  if (providedBuf.length !== expectedBuf.length || !timingSafeEqual(providedBuf, expectedBuf)) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Missing or invalid X-API-Key header'
    });
  }

  next();
}
