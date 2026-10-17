/**
 * How a real value is adapted to where its ticket sits (design §3,
 * "Swap-path hardening"). Returning null refuses the value.
 */

/** Percent-encode control, space and non-ASCII characters (UTF-8), leaving everything else as is. */
export function percentEncodeUnsafe(text: string): string {
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  return text.replace(/[\u0000-\u0020\u007f-\uffff]+/g, run =>
    [...Buffer.from(run, 'utf8')].map(b => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join(''));
}

/**
 * A header field value: refused when it holds a control character other than
 * tab (RFC 9110 §5.5). CR/LF would add header lines.
 */
export function headerFieldValue(value: string): string | null {
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  return /[\u0000-\u0008\u000a-\u001f\u007f]/.test(value) ? null : value;
}
