"""Shared canonical serialization and bounded, atomic local storage."""
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone


class VoteError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def b64(value):
    return base64.b64encode(value).decode('ascii')


def unb64(value):
    return base64.b64decode(value, validate=True)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def read_json(path, limit=16_000_000):
    path = Path(path)
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise VoteError('JSON包含重复字段')
            out[k] = v
        return out
    def reject_constant(value):
        raise VoteError('JSON不允许NaN或Infinity')
    try:
        # Bound the actual read too, in case a file changes after stat().
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise VoteError('文件超过允许大小')
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VoteError('无法读取有效JSON文件：' + path.name) from exc


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        temp.write_bytes(canonical(value))
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
