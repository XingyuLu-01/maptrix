from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

import pandas as pd


@dataclass
class Issue:
    severity: str          # HIGH/MEDIUM/LOW
    rule_id: str
    title: str
    cons_unit: str
    dataset: str
    record_id: str
    country: str
    details: str
    suggested_action: str


def safe_str(x) -> str:
    if pd.isna(x):
        return ""
    return str(x).strip()


def coerce_date(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series.replace("", pd.NA), errors="coerce")


def ensure_cols(df: pd.DataFrame, required: List[str], name: str) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{name} missing columns: {missing}. Available: {list(df.columns)}")


def read_workbook(path: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    xls = pd.ExcelFile(path)

    def rs(sheet: str, required: bool) -> pd.DataFrame:
        if sheet in xls.sheet_names:
            df = pd.read_excel(xls, sheet_name=sheet)
            df.columns = [safe_str(c) for c in df.columns]
            for c in df.columns:
                if df[c].dtype == object:
                    df[c] = df[c].map(safe_str)
            return df
        return pd.DataFrame() if not required else (_raise_missing(sheet, xls.sheet_names))

    cu = rs("consolidation_units", True)
    leases = rs("leases", False)
    emp = rs("employees", False)
    sites = rs("production_sites", False)
    return cu, leases, emp, sites


def _raise_missing(sheet: str, names) -> pd.DataFrame:
    raise ValueError(f"Missing required sheet '{sheet}'. Found: {names}")


def normalize_cons_unit(df: pd.DataFrame) -> pd.Series:
    if df is None or df.empty or "cons_unit" not in df.columns:
        return pd.Series([], dtype=str)
    return df["cons_unit"].astype(str).str.strip()


def apply_mappings(df: pd.DataFrame, mappings: Dict[str, str]) -> pd.DataFrame:
    """
    Apply from_cons_unit -> to_cons_unit mapping on any df that contains cons_unit.
    """
    if df is None or df.empty or "cons_unit" not in df.columns or not mappings:
        return df
    out = df.copy()
    out["cons_unit"] = out["cons_unit"].astype(str).str.strip().map(lambda x: mappings.get(x, x))
    return out


def compute_coverage(master: pd.DataFrame, df: pd.DataFrame) -> Dict[str, object]:
    m = set(normalize_cons_unit(master))
    d = set(normalize_cons_unit(df))
    return {
        "master_total": len(m),
        "dataset_total": len(d),
        "matched": len(m & d),
        "unknown": len(d - m),
        "missing": len(m - d),
        "unknown_set": sorted(d - m),
        "missing_set": sorted(m - d),
    }


def compute_coverage_matrix(cu: pd.DataFrame, leases: pd.DataFrame, emp: pd.DataFrame, sites: pd.DataFrame) -> pd.DataFrame:
    master = sorted(set(normalize_cons_unit(cu)))
    leases_set = set(normalize_cons_unit(leases))
    emp_set = set(normalize_cons_unit(emp))
    sites_set = set(normalize_cons_unit(sites))

    rows = []
    for unit in master:
        rows.append({
            "cons_unit": unit,
            "in_leases": unit in leases_set,
            "in_employees": unit in emp_set,
            "in_sites": unit in sites_set,
        })
    return pd.DataFrame(rows)


def run_rules(cu: pd.DataFrame, leases: pd.DataFrame, emp: pd.DataFrame, sites: pd.DataFrame) -> List[Issue]:
    issues: List[Issue] = []
    ensure_cols(cu, ["cons_unit", "cons_unit_name", "country", "company_name"], "consolidation_units")
    cu_set = set(normalize_cons_unit(cu))

    # Employees
    if not emp.empty:
# Required minimal columns for employees
ensure_cols(emp, ["cons_unit"], "employees")

# Normalize optional names / aliases
emp = emp.copy()

# cons_unit_name optional: derive if missing
if "cons_unit_name" not in emp.columns:
    if "unit_name" in emp.columns:
        emp["cons_unit_name"] = emp["unit_name"]
    else:
        emp["cons_unit_name"] = ""

# R&D column: accept either rd_FTEs or r_and_d_FTEs
if "r_and_d_FTEs" not in emp.columns and "rd_FTEs" in emp.columns:
    emp["r_and_d_FTEs"] = emp["rd_FTEs"]

# If still missing, create as 0
for col in ["admin_FTEs", "service_production_FTEs", "legal_FTEs", "r_and_d_FTEs", "sales_mkt_FTEs"]:
    if col not in emp.columns:
        emp[col] = 0
        fte_cols = ["admin_FTEs", "service_production_FTEs", "legal_FTEs", "r_and_d_FTEs", "sales_mkt_FTEs"]
        for c in fte_cols:
            emp[c] = pd.to_numeric(emp[c], errors="coerce").fillna(0)
        emp["total_FTEs"] = emp[fte_cols].sum(axis=1)

        unknown = emp.loc[~emp["cons_unit"].isin(cu_set)]
        for _, r in unknown.iterrows():
            issues.append(Issue("HIGH", "R101", "Employees record references unknown cons_unit",
                               r["cons_unit"], "employees", "", "", 
                               "cons_unit appears in employees but not in consolidation_units master list.",
                               "Fix cons_unit code OR add missing cons_unit to consolidation_units extract."))

    # Leases
    if not leases.empty:
        ensure_cols(leases, ["cons_unit", "country", "company_code", "contract_name", "start_date", "end_date", "facility_type"], "leases")
        if "lease_id" not in leases.columns:
            leases["lease_id"] = ""

        leases["start_dt"] = coerce_date(leases["start_date"])
        leases["end_dt"] = coerce_date(leases["end_date"])

        unknown = leases.loc[~leases["cons_unit"].isin(cu_set)]
        for _, r in unknown.iterrows():
            issues.append(Issue("HIGH", "R201", "Lease references unknown cons_unit",
                               r["cons_unit"], "leases", str(r.get("lease_id","")), str(r.get("country","")),
                               f"Lease '{r.get('contract_name','')}' uses cons_unit not in consolidation_units.",
                               "Fix cons_unit code OR ensure consolidation_units extract includes this unit."))

        bad_dates = leases.loc[leases["start_dt"].isna() | leases["end_dt"].isna()]
        for _, r in bad_dates.iterrows():
            issues.append(Issue("MEDIUM", "R202", "Lease has missing or invalid start/end date",
                               str(r.get("cons_unit","")), "leases", str(r.get("lease_id","")), str(r.get("country","")),
                               f"start_date='{r.get('start_date','')}', end_date='{r.get('end_date','')}'",
                               "Correct lease start/end dates to enable quarter-based checks."))

        inverted = leases.loc[leases["start_dt"].notna() & leases["end_dt"].notna() & (leases["end_dt"] < leases["start_dt"])]
        for _, r in inverted.iterrows():
            issues.append(Issue("HIGH", "R203", "Lease end_date is earlier than start_date",
                               str(r.get("cons_unit","")), "leases", str(r.get("lease_id","")), str(r.get("country","")),
                               f"Lease '{r.get('contract_name','')}' has end_date < start_date.",
                               "Fix inverted lease dates."))

        missing_ft = leases.loc[leases["facility_type"].astype(str).str.strip() == ""]
        for _, r in missing_ft.iterrows():
            issues.append(Issue("LOW", "R204", "Lease missing facility_type",
                               str(r.get("cons_unit","")), "leases", str(r.get("lease_id","")), str(r.get("country","")),
                               f"Lease '{r.get('contract_name','')}' has blank facility_type.",
                               "Fill facility_type to support footprint classification."))

    # Sites
    if not sites.empty:
        ensure_cols(sites, ["cons_unit", "country", "site_name"], "production_sites")
        if "site_id" not in sites.columns:
            sites["site_id"] = ""

        unknown = sites.loc[~sites["cons_unit"].isin(cu_set)]
        for _, r in unknown.iterrows():
            issues.append(Issue("HIGH", "R301", "Production site references unknown cons_unit",
                               r["cons_unit"], "production_sites", str(r.get("site_id","")), str(r.get("country","")),
                               f"Site '{r.get('site_name','')}' uses cons_unit not in consolidation_units.",
                               "Fix cons_unit mapping OR add missing cons_unit to consolidation_units."))

    # Cross checks
    leases_set = set(normalize_cons_unit(leases))
    sites_set = set(normalize_cons_unit(sites))

    if not emp.empty:
        emp_tot = emp.groupby("cons_unit", as_index=True)["total_FTEs"].sum()
        for unit in sorted(set(normalize_cons_unit(emp)) & cu_set):
            if float(emp_tot.get(unit, 0)) > 0 and unit not in leases_set:
                issues.append(Issue("MEDIUM", "R401", "Employees exist but no leases for cons_unit",
                                   unit, "cross", "", "",
                                   f"total_FTEs={float(emp_tot.get(unit,0)):.0f} but no leases found.",
                                   "Lease extract may be incomplete, or facilities are owned; document boundary logic."))

        if not leases.empty:
            for unit in sorted(leases_set & cu_set):
                if float(emp_tot.get(unit, 0)) == 0:
                    issues.append(Issue("LOW", "R402", "Leases exist but employees are zero for cons_unit",
                                       unit, "cross", "", "",
                                       "Lease footprint exists but HR shows 0 FTEs.",
                                       "Confirm outsourcing/shared services or missing HR data."))

    if not sites.empty:
        for unit in sorted(sites_set & cu_set):
            if unit not in leases_set:
                issues.append(Issue("MEDIUM", "R403", "Production sites exist but no leases for cons_unit",
                                   unit, "cross", "", "",
                                   "Site list shows locations but lease register has none.",
                                   "Check owned-vs-leased or missing lease extraction."))

    return issues


def issues_to_frames(issues: List[Issue]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    df = pd.DataFrame([i.__dict__ for i in issues])
    if df.empty:
        summary = pd.DataFrame(columns=["severity", "rule_id", "title", "count"])
    else:
        summary = (df.groupby(["severity", "rule_id", "title"], as_index=False)
                     .size()
                     .rename(columns={"size": "count"})
                     .sort_values(["severity", "count"], ascending=[True, False]))
    return df, summary


def compute_risk_score(issues_df: pd.DataFrame, coverage: Dict[str, Dict[str, object]]) -> float:
    """
    Simple, explainable risk score 0-100 based on:
      - HIGH issues
      - MEDIUM issues
      - unknown cons_units in datasets
      - missing coverage
    """
    if issues_df is None or issues_df.empty:
        base = 0.0
    else:
        hi = int((issues_df["severity"] == "HIGH").sum())
        med = int((issues_df["severity"] == "MEDIUM").sum())
        low = int((issues_df["severity"] == "LOW").sum())
        base = hi * 10 + med * 4 + low * 1

    unknown = 0
    missing = 0
    for cov in coverage.values():
        unknown += int(cov.get("unknown", 0))
        missing += int(cov.get("missing", 0))

    score = base + unknown * 6 + missing * 2
    return float(min(100.0, score))


def diff_runs(prev_cov_matrix: pd.DataFrame, curr_cov_matrix: pd.DataFrame) -> pd.DataFrame:
    """
    Compare coverage matrix between runs.
    Outputs changes in in_leases/in_employees/in_sites per cons_unit.
    """
    if prev_cov_matrix is None or prev_cov_matrix.empty:
        out = curr_cov_matrix.copy()
        out["change"] = "NEW_RUN_BASELINE"
        return out

    prev = prev_cov_matrix.set_index("cons_unit")
    curr = curr_cov_matrix.set_index("cons_unit")

    all_units = sorted(set(prev.index) | set(curr.index))
    rows = []

    for u in all_units:
        p = prev.loc[u] if u in prev.index else None
        c = curr.loc[u] if u in curr.index else None

        if p is None:
            rows.append({"cons_unit": u, "change": "ADDED", "in_leases": c["in_leases"], "in_employees": c["in_employees"], "in_sites": c["in_sites"]})
            continue
        if c is None:
            rows.append({"cons_unit": u, "change": "REMOVED", "in_leases": p["in_leases"], "in_employees": p["in_employees"], "in_sites": p["in_sites"]})
            continue

        changed = (bool(p["in_leases"]) != bool(c["in_leases"]) or bool(p["in_employees"]) != bool(c["in_employees"]) or bool(p["in_sites"]) != bool(c["in_sites"]))
        if changed:
            rows.append({"cons_unit": u, "change": "CHANGED", "in_leases": c["in_leases"], "in_employees": c["in_employees"], "in_sites": c["in_sites"]})

    return pd.DataFrame(rows)