import Cookie from 'cookie';

type APIRes<T> = T | ErrorBase | APIError;
type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
type ReqData = URLSearchParams | Dict | undefined | unknown;

/**
 * Type guard to determine if an API response is a detailed error.
 *
 * @param data API JSON Response
 * @returns Type guard for `data`.
 */
export function isApiError(data: Record<string, unknown>): data is APIError {
  return 'error' in data && 'exception' in data;
}

/**
 * Type guard to determine if an API response is an error.
 *
 * @param data API JSON Response
 * @returns Type guard for `data`.
 */
export function hasError(data: Record<string, unknown>): data is ErrorBase {
  return 'error' in data;
}

/**
 * Type guard to determine if an element is an `HTMLInputElement`.
 *
 * @param element HTML Element.
 */
export function isInputElement(element: HTMLElement): element is HTMLInputElement {
  return 'value' in element && 'required' in element;
}

/**
 * Retrieve the CSRF token from cookie storage.
 */
export function getCsrfToken(): string {
  // Prefer a token embedded in the DOM (works when CSRF cookie is HttpOnly)
  const input = document.querySelector<HTMLInputElement>('input[name="csrfmiddlewaretoken"]');
  if (input && input.value) {
    return input.value;
  }
  // Fallback to cookie when available
  const { csrftoken: csrfToken } = Cookie.parse(document.cookie);
  if (typeof csrfToken === 'undefined') {
    throw new Error('Invalid or missing CSRF token');
  }
  return csrfToken;
}

/**
 * Authenticate and interact with the NetBox API.
 *
 * @param url Request URL
 * @param method Request Method
 * @param data Data to `POST`, `PATCH`, or `PUT`, if applicable.
 * @returns JSON Response
 */
export async function apiRequest<R extends Dict, D extends ReqData = undefined>(
  url: string,
  method: Method,
  data?: D,
): Promise<APIRes<R>> {
  const headers = new Headers();
  // Only include CSRF token for non-GET methods; if missing, continue so UI can surface server error.
  if (method !== 'GET') {
    try {
      const token = getCsrfToken();
      headers.set('X-CSRFToken', token);
    } catch (e) {
      // No CSRF cookie available; proceed without header to let server respond (e.g., 403)
    }
  }

  let body;
  if (typeof data !== 'undefined') {
    body = JSON.stringify(data);
    headers.set('content-type', 'application/json');
    headers.set('Accept', 'application/json');
  }

  const res = await fetch(url, { method, body, headers, credentials: 'same-origin' });
  const contentType = res.headers.get('Content-Type');
  if (typeof contentType === 'string' && contentType.includes('text')) {
    const error = await res.text();
    return { error } as ErrorBase;
  }
  const json = (await res.json()) as R | APIError;
  if (!res.ok && Array.isArray(json)) {
    const error = json.join('\n');
    return { error } as ErrorBase;
  } else if (!res.ok && 'detail' in json) {
    return { error: json.detail } as ErrorBase;
  }
  return json;
}

/**
 * `POST` an object as form data to the NetBox API.
 *
 * @param url Request URL
 * @param data Object to convert to form data
 * @returns JSON Response
 */
export async function apiPostForm<R extends Dict, D extends Dict>(
  url: string,
  data: D,
): Promise<APIRes<R>> {
  return await apiRequest<R, D>(url, 'POST', data);
}

/**
 * `GET` data from the NetBox API.
 *
 * @param url Request URL
 * @returns JSON Response
 */
export async function apiGetBase<R extends Dict>(url: string): Promise<APIRes<R>> {
  return await apiRequest<R>(url, 'GET');
}

/**
 * Prefix a NetBox-relative path with the configured BASE_PATH derived from the current location.
 *
 * Example: with BASE_PATH 'netbox/', window.location.pathname might be '/netbox/plugins/...'.
 * This derives '/netbox' and prefixes it to the provided path (e.g., '/api/...').
 */
export function withBasePath(path: string): string {
  const pathname = window.location.pathname || '';
  const pluginsIdx = pathname.indexOf('/plugins/');
  const apiIdx = pathname.indexOf('/api/');
  const cutIdx = pluginsIdx >= 0 ? pluginsIdx : apiIdx;
  const base = cutIdx >= 0 ? pathname.slice(0, cutIdx) : '';
  return `${base}${path}`;
}
