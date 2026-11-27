"""One tiny object-store interface used for encrypted blobs AND ledger anchors:
put(key, data, once=False) / get(key) / keys(prefix). `once=True` must refuse to overwrite."""
import pathlib


class LocalStore:
    """Dev/test store. Tested."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, data: bytes, once: bool = False) -> None:
        p = self.root / key
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "xb" if once else "wb") as f:  # "x" raises FileExistsError
            f.write(data)

    def get(self, key: str) -> bytes:
        return (self.root / key).read_bytes()

    def keys(self, prefix: str) -> list[str]:
        base = self.root / prefix
        return sorted(p.relative_to(self.root).as_posix() for p in base.rglob("*") if p.is_file()) if base.exists() else []


class S3Store:
    """Production store. NOT covered by the test-suite (needs real AWS).
    IAM: s3:PutObject, s3:GetObject, s3:ListBucket on this bucket only; no s3:DeleteObject.
    Bucket: Block Public Access, versioning, Object Lock (needed so anchors cannot be replaced), lifecycle rule to expire
    objects tagged/prefixed as uncommitted. `once=True` uses a conditional write (If-None-Match)."""

    def __init__(self, bucket: str):
        import boto3

        self.bucket, self.c = bucket, boto3.client("s3")

    def put(self, key: str, data: bytes, once: bool = False) -> None:
        extra = {"IfNoneMatch": "*"} if once else {}
        try:
            self.c.put_object(Bucket=self.bucket, Key=key, Body=data, ServerSideEncryption="AES256", **extra)
        except self.c.exceptions.ClientError as e:
            if once and e.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise FileExistsError(key) from e
            raise

    def get(self, key: str) -> bytes:
        return self.c.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def keys(self, prefix: str) -> list[str]:
        pages = self.c.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix)
        return sorted(o["Key"] for page in pages for o in page.get("Contents", []))
