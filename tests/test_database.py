from datetime import datetime, timezone

from src.database import AlertDatabase
from src.models import Alert


def test_database_persists_alerts_and_statistics(tmp_path):
    db_path = tmp_path / "alerts.db"
    database = AlertDatabase(str(db_path))

    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        severity="HIGH",
        rule_name="PORT_SCAN",
        source_ip="10.0.0.11",
        destination_ip="10.0.0.9",
        description="Port scan detected",
        evidence={"ports": [22, 23, 80]},
        metadata={"detector": "unit-test"},
    )
    database.add_alert(alert)

    recent = database.get_recent_alerts(10)
    stats = database.get_statistics()

    assert len(recent) == 1
    assert recent[0]["rule_name"] == "PORT_SCAN"
    assert stats["total"] == 1
    assert stats["high"] == 1
    database.close()
