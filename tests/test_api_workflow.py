def test_root_documents_python_runtime_and_enterprise_endpoints(client):
    response = client.get("/")

    assert response.status_code == 200
    body = response.json()
    assert body["runtime"]["language"] == "python"
    assert body["runtime"]["framework"] == "fastapi"
    assert body["docs"] == "/docs"
    assert body["endpoints"]["log_analytics_query"] == "POST /integrations/log-analytics/query"
    assert body["endpoints"]["resource_graph_discovery"] == (
        "POST /integrations/resource-graph/discover"
    )


def test_ingest_and_approve_vmss_alert(client, sample_alert):
    ingest_response = client.post("/alerts/azure-monitor", json=sample_alert)
    assert ingest_response.status_code == 200
    body = ingest_response.json()
    assert body["status"] == "open"
    assert len(body["action_ids"]) == 1

    incident_id = body["incident_id"]
    incident = client.get(f"/incidents/{incident_id}").json()
    assert "VMSS capacity pressure" in incident["summary"]

    actions = client.get(f"/incidents/{incident_id}/actions").json()
    assert actions[0]["type"] == "resize_vmss"
    assert actions[0]["status"] == "proposed"

    approve = client.post(
        f"/incidents/{incident_id}/approve",
        json={"approver": "operator@example.com", "comment": "Approved in test"},
    )
    assert approve.status_code == 200
    result = approve.json()[0]
    assert result["status"] == "succeeded"
    assert "Mock execution completed" in result["output"]

    action = client.get(f"/actions/{body['action_ids'][0]}").json()
    assert action["approved_by"] == "operator@example.com"
    assert action["status"] == "succeeded"


def test_reject_incident_rejects_proposed_actions(client, sample_alert):
    incident_id = client.post("/alerts/azure-monitor", json=sample_alert).json()["incident_id"]

    response = client.post(
        f"/incidents/{incident_id}/reject",
        json={"rejected_by": "lead@example.com", "reason": "Duplicate incident"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    actions = client.get(f"/incidents/{incident_id}/actions").json()
    assert actions[0]["status"] == "rejected"
