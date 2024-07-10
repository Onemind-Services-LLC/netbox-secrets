export type APIKeyPair = {
    public_key: string;
    private_key: string;
};

export type APISecret = {
    assigned_object: APIObjectBase;
    assigned_object_id: number;
    assigned_object_type: string;
    created: string;
    custom_fields: Record<string, unknown>;
    display: string;
    hash: string;
    id: number;
    last_updated: string;
    name: string;
    plaintext: string | null;
    role: APIObjectBase;
    tags: number[];
    url: string;
};
