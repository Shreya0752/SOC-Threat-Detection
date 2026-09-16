html = open("frontend/index.html", "r", encoding="utf-8").read()

pos = html.find("function IncidentInvestigationModal")
end = html.find("function RiskDashboardView", pos)
open("scratch/modal_code.txt", "w", encoding="utf-8").write(html[pos:end])
print("Saved modal_code.txt")
