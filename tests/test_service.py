from app.service import parse_progress

def test_progress_does_not_fail_on_empty_error_key():
    status, percent, _ = parse_progress({"status": "Running", "error": [], "percentage": 42})
    assert status == "migrating"
    assert percent == 42

def test_progress_completed():
    status, percent, _ = parse_progress({"responseData": {"status": "Completed", "progressPercent": 100}})
    assert status == "completed"
    assert percent == 100

def test_progress_failed_only_on_mailbox_status():
    status, _, _ = parse_progress({"status": "Failed", "failedItems": 2})
    assert status == "failed"

def test_failed_item_does_not_fail_active_mailbox():
    status, _, _ = parse_progress({"status": "Running", "failedItems": 2, "migratedItems": 48000})
    assert status == "migrating"
