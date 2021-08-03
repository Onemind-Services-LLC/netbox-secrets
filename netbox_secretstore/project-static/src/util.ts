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
 * Retrieve the CSRF token from cookie storage.
 */
export function getCsrfToken(): string {
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
  const token = getCsrfToken();
  const headers = new Headers({ 'X-CSRFToken': token });

  let body;
  if (typeof data !== 'undefined') {
    let obj;
    if (typeof data === 'object' ) {
      obj = Object.fromEntries(data.entries());
    } else {
      obj = data;
    }
    body = JSON.stringify(obj);
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
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) {
    body.append(k, String(v));
  }
  return await apiRequest<R, URLSearchParams>(url, 'POST', body);
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
