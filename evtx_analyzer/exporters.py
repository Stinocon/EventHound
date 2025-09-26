import csv
import orjson
from typing import Dict, Optional, List


class JsonlExporter:
    def __init__(self, path: str) -> None:
        self.f = open(path, 'wb')

    def write(self, evt: Dict) -> None:
        data = {k: v for k, v in evt.items() if k != 'timestamp_dt'}
        self.f.write(orjson.dumps(data))
        self.f.write(b"\n")

    def close(self) -> None:
        self.f.close()


class CsvExporter:
    def __init__(self, path: str) -> None:
        self.f = open(path, 'w', newline='', encoding='utf-8')
        self.writer = None

    def write(self, evt: Dict) -> None:
        data = {k: v for k, v in evt.items() if k != 'timestamp_dt'}
        if self.writer is None:
            fieldnames = ['timestamp', 'channel', 'event_id', 'computer', 'provider', 'record_id', 'user_sid', 'data']
            self.writer = csv.DictWriter(self.f, fieldnames=fieldnames)
            self.writer.writeheader()
        row = {
            'timestamp': data.get('timestamp'),
            'channel': data.get('channel'),
            'event_id': data.get('event_id'),
            'computer': data.get('computer'),
            'provider': data.get('provider'),
            'record_id': data.get('record_id'),
            'user_sid': data.get('user_sid'),
            'data': orjson.dumps(data.get('data')).decode('utf-8') if data.get('data') is not None else ''
        }
        self.writer.writerow(row)

    def close(self) -> None:
        self.f.close()


class ParquetExporter:
    def __init__(self, path: str, batch_size: int = 5000) -> None:
        import pyarrow as pa
        import pyarrow.parquet as pq
        self.pa = pa
        self.pq = pq
        self.path = path
        self.batch_size = batch_size
        self.rows: List[Dict] = []
        self.schema = pa.schema([
            pa.field('timestamp', pa.string()),
            pa.field('channel', pa.string()),
            pa.field('event_id', pa.string()),
            pa.field('computer', pa.string()),
            pa.field('provider', pa.string()),
            pa.field('record_id', pa.string()),
            pa.field('user_sid', pa.string()),
            pa.field('data', pa.string()),
        ])
        self.writer = None

    def write(self, evt: Dict) -> None:
        data = {k: v for k, v in evt.items() if k != 'timestamp_dt'}
        row = {
            'timestamp': data.get('timestamp'),
            'channel': data.get('channel'),
            'event_id': str(data.get('event_id')) if data.get('event_id') is not None else None,
            'computer': data.get('computer'),
            'provider': data.get('provider'),
            'record_id': str(data.get('record_id')) if data.get('record_id') is not None else None,
            'user_sid': data.get('user_sid'),
            'data': orjson.dumps(data.get('data')).decode('utf-8') if data.get('data') is not None else None,
        }
        self.rows.append(row)
        if len(self.rows) >= self.batch_size:
            self._flush()

    def _flush(self) -> None:
        if not self.rows:
            return
        table = self.pa.Table.from_pylist(self.rows, schema=self.schema)
        if self.writer is None:
            self.writer = self.pq.ParquetWriter(self.path, table.schema)
        self.writer.write_table(table)
        self.rows.clear()

    def close(self) -> None:
        self._flush()
        if self.writer is not None:
            self.writer.close()


class FindingsJsonlExporter:
    def __init__(self, path: str) -> None:
        self.f = open(path, 'wb')

    def write(self, finding: Dict) -> None:
        self.f.write(orjson.dumps(finding))
        self.f.write(b"\n")

    def close(self) -> None:
        self.f.close()


class FindingsCsvExporter:
    def __init__(self, path: str) -> None:
        self.f = open(path, 'w', newline='', encoding='utf-8')
        self.writer = csv.DictWriter(self.f, fieldnames=['event_timestamp', 'channel', 'event_id', 'rule_id', 'severity', 'description', 'tags'])
        self.writer.writeheader()

    def write(self, finding: Dict) -> None:
        row = {
            'event_timestamp': finding.get('event_timestamp'),
            'channel': finding.get('channel'),
            'event_id': finding.get('event_id'),
            'rule_id': finding.get('rule_id'),
            'severity': finding.get('severity'),
            'description': finding.get('description'),
            'tags': ','.join(finding.get('tags') or []),
        }
        self.writer.writerow(row)

    def close(self) -> None:
        self.f.close()
