type Dict<T extends unknown = unknown> = Record<string, T>; // eslint-disable-line @typescript-eslint/no-unnecessary-type-constraint

type Primitives = string | number | boolean | undefined | null;

type JSONAble = Primitives | Primitives[] | { [k: string]: JSONAble } | JSONAble[];

/**
 * Base NetBox API Error.
 */
type ErrorBase = {
    error: string;
};

/**
 * NetBox API error with details.
 */
type APIError = {
    exception: string;
    netbox_version: string;
    python_version: string;
} & ErrorBase;

/**
 * NetBox API Object.
 */
type APIObjectBase = {
    id: number;
    display: string;
    name?: string | null;
    url: string;
    [k: string]: JSONAble;
};

interface Window {
    Modal: typeof import('bootstrap').Modal;
    Toast: typeof import('bootstrap').Toast;
}
