"""REST API for advanced NetGuard intelligence."""
from flask import Blueprint,jsonify,request
from advanced_intelligence import analyze,forecast,heuristic_risk,security,root_cause,impact,correlate,runbook
advanced_bp=Blueprint("advanced_intelligence",__name__)
def body():
    x=request.get_json(silent=True);return x if isinstance(x,dict) else {}
def dicts(p,k):
    v=p.get(k,[]);return [x for x in v if isinstance(x,dict)] if isinstance(v,list) else []
def obj(p,k):
    v=p.get(k,{});return v if isinstance(v,dict) else {}
@advanced_bp.get("/api/intelligence/capabilities")
def capabilities():return jsonify({"success":True,"modules":["MULTI_HORIZON_FORECAST","EXPLAINABLE_RISK","SECURITY_ANOMALY","INCIDENT_CORRELATION","ROOT_CAUSE_ANALYSIS","BLAST_RADIUS","FAILURE_SIMULATION","REMEDIATION_RUNBOOK"]})
@advanced_bp.post("/api/intelligence/analyze")
def analyze_route():
    p=body();return jsonify({"success":True,"device_analysis":[analyze(x) for x in dicts(p,"devices")]})
@advanced_bp.post("/api/intelligence/root-cause")
def root_route():
    p=body();return jsonify({"success":True,**root_cause(dicts(p,"devices"),dicts(p,"links"),dicts(p,"incidents"))})
@advanced_bp.post("/api/intelligence/correlate")
def correlate_route():
    p=body();return jsonify({"success":True,"groups":correlate(dicts(p,"incidents"),dicts(p,"links"))})
@advanced_bp.post("/api/intelligence/impact")
def impact_route():
    p=body();return jsonify({"success":True,**impact(str(p["root_device"]) if p.get("root_device") is not None else None,dicts(p,"nodes"),dicts(p,"links"))})
@advanced_bp.post("/api/intelligence/security")
def security_route():
    p=body();return jsonify({"success":True,"events":security(obj(p,"telemetry") or p)})
@advanced_bp.post("/api/intelligence/simulate")
def simulate_route():
    p=body();telemetry=obj(p,"telemetry");base=dict(telemetry)
    for k,v in obj(p,"changes").items():
        try:base[k]=float(v)
        except (TypeError,ValueError):base[k]=v
    events=security(base)
    return jsonify({"success":True,"baseline_risk":heuristic_risk(telemetry),"simulated_risk":heuristic_risk(base),"forecast":forecast(p.get("failure_probability"),base),"security_anomalies":events,"remediation":runbook(base,events,p.get("diagnosis","UNKNOWN"))})
@advanced_bp.post("/api/intelligence/remediation")
def remediation_route():
    p=body();return jsonify({"success":True,**runbook(obj(p,"telemetry"),dicts(p,"security_events"),p.get("diagnosis","UNKNOWN"))})
