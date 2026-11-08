import apsw
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from nettacker.database.db import remove_old_logs
from nettacker.database.models import HostsLog


@pytest.mark.parametrize("use_apsw", [True, False], ids=["apsw", "sqlalchemy"])
@pytest.mark.parametrize("compare_id", [None, "comparison", "current", ""])
def test_remove_old_logs_preserves_only_requested_scans(
    tmp_path, monkeypatch, use_apsw, compare_id
):
    """Cleanup must commit without deleting current, comparison, or unrelated findings."""
    db_path = tmp_path / "scan-events.db"
    engine = create_engine(f"sqlite:///{db_path}")
    HostsLog.__table__.create(engine)
    rows = [
        {"target": "example.test", "module_name": "port_scan", "scan_unique_id": scan_id}
        for scan_id in ("current", "comparison", "old", "")
    ]
    rows.extend(
        [
            {"target": "other.test", "module_name": "port_scan", "scan_unique_id": "old"},
            {"target": "example.test", "module_name": "http_scan", "scan_unique_id": "old"},
        ]
    )
    with engine.begin() as connection:
        connection.execute(HostsLog.__table__.insert(), rows)

    session = None
    if use_apsw:
        connection = apsw.Connection(str(db_path))
        db_connection = (connection, connection.cursor())
    else:
        session = Session(engine)
        db_connection = session
    monkeypatch.setattr("nettacker.database.db.create_connection", lambda: db_connection)

    try:
        assert remove_old_logs(
            {
                "target": "example.test",
                "module_name": "port_scan",
                "scan_id": "current",
                "scan_compare_id": compare_id,
            }
        )
        # A fresh connection verifies that the deletion was committed.
        with engine.connect() as connection:
            remaining = set(
                connection.execute(
                    select(HostsLog.target, HostsLog.module_name, HostsLog.scan_unique_id)
                ).all()
            )
        expected = {
            ("example.test", "port_scan", "current"),
            ("other.test", "port_scan", "old"),
            ("example.test", "http_scan", "old"),
        }
        if compare_id is not None:
            expected.add(("example.test", "port_scan", compare_id))
        assert remaining == expected
    finally:
        if session is not None:
            session.close()
        engine.dispose()
