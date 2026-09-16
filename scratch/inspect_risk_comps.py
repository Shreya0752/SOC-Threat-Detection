import re

html = open("frontend/index.html", "r", encoding="utf-8").read()

for comp in ["RiskKPICards", "RiskDistributionChart", "RiskTrendChart", "TopPriorityIncidentsTable", "IncidentInvestigationModal", "RiskDashboardView"]:
    pos = html.find(f"function {comp}")
    if pos != -1:
        end = html.find("\n    function ", pos + 10)
        if end == -1:
            end = html.find("\n    const ", pos + 10)
        snippet = html[pos:pos+1500]
        print(f"=== {comp} ===")
        print(snippet[:600])
        print("...")
