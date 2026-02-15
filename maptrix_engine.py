# maptrix_engine.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional

import pandas as pd


# =========================
# Utilities
# =========================
def _clean_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def _as_str_series(s: pd.Series) -> pd.Series:
    return s.astype(str).fillna("").str.strip()


def ensure_cols(df: pd.DataFrame, required: List[str], name: str) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{name} missing columns: {missing}. Available: {list(df.columns)}")


def _ensure_numeric(df: pd.DataFrame, cols: List[str], default: float = 0.0) -> pd.DataFrame:
    out = df.copy()
    for c in cols:
        if c not in out.columns:
            out[c] = default
        out[c] = pd.to_numeric(out[c], errors="coerce").fillna(default)
    return out


def _norm_cons_unit(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "cons_unit" in out.columns:
        out["cons_unit"] = _as_str_series(out["cons_unit"])
    return out


def _norm_country(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "country" in out.columns:
        out["country"] = _as_str_series(out["country"])
    return out


def apply_mappings(df: pd.DataFrame, mapping: Dict[str, str]) -> pd.DataFrame:
    """
    Apply cons_unit mapping memory: replace df['cons_unit'] values if in mapping dict.
    mapping: {from_cons_unit: to_cons_unit}
    """
    if df is None or df.empty or "cons_unit" not in df.columns:
        return df if df is not None else pd.DataFrame()
    out = df.copy()
    out["cons_unit"] = _as_str_series(out["cons_unit"]).map(lambda x: mapping.get(x, x))
    return out


# =========================
# Issues model
# =========================
@dataclass
class Issue:
    severity: str               # "HIGH" | "MEDIUM" | "LOW"
    rule_id: str                # e.g. "CU_001"
    title: str                  # short
    cons_unit: str              # canonical cons_unit
    dataset: str                # consolidation_units | leases | employees | production_sites
    record_id: str              # identifier (string)
    country: str                # best-known
    details: str                # explanation
    suggested_action: str       # what to do


def _issue(
    severity: str,
    rule_id: str,
    title: str,
    cons_unit: str,
    dataset: str,
    record_id: str = "",
    country: str = "",
    details: str = "",
    suggested_action: str = "",
) -> Issue:
    return Issue(
        severity=severity,
        rule_id=rule_id,
        title=title,
        cons_unit=str(cons_unit or "").strip(),
        dataset=dataset,
        record_id=str(record_id or "").strip(),
        country=str(country or "").strip(),
        details=details,
        suggested_action=suggested_action,
    )


# =========================
# Normalization per dataset (engine-side safety net)
# =========================
def normalize_consolidation_units(cu: pd.DataFrame) -> pd.DataFrame:
    cu = _clean_cols(cu)
    ensure_cols(cu, ["cons_unit", "country", "company_name"], "consolidation_units")
    cu = _norm_cons_unit(_norm_country(cu))

    # optional cons_unit_name
    if "cons_unit_name" not in cu.columns:
        cu = cu.copy()
        cu["cons_unit_name"] = cu["company_name"]

    return cu


def normalize_leases(leases: pd.DataFrame) -> pd.DataFrame:
    if leases is None or leases.empty:
        return pd.DataFrame(columns=["cons_unit", "country", "company_code", "contract_name", "start_date", "end_date", "facility_type"])

    leases = _clean_cols(leases)
    ensure_cols(leases, ["cons_unit"], "leases")
    leases = _norm_cons_unit(_norm_country(leases))

    # create optional columns if missing
    for c in ["country", "company_code", "contract_name", "start_date", "end_date", "facility_type"]:
        if c not in leases.columns:
            leases[c] = ""

    # dates as strings (safe)
    for c in ["start_date", "end_date"]:
        leases[c] = leases[c].astype(str).fillna("").str.strip()

    return leases


def normalize_employees(emp: pd.DataFrame) -> pd.DataFrame:
    if emp is None or emp.empty:
        return pd.DataFrame(columns=[
            "cons_unit", "cons_unit_name",
            "admin_FTEs", "service_production_FTEs", "legal_FTEs", "r_and_d_FTEs", "sales_mkt_FTEs"
        ])

    emp = _clean_cols(emp)
    ensure_cols(emp, ["cons_unit"], "employees")
    emp = _norm_cons_unit(emp)

    emp = emp.copy()

    # Optional name columns
    if "cons_unit_name" not in emp.columns:
        if "unit_name" in emp.columns:
            emp["cons_unit_name"] = emp["unit_name"]
        else:
            emp["cons_unit_name"] = ""

    # Accept rd_FTEs alias
    if "r_and_d_FTEs" not in emp.columns and "rd_FTEs" in emp.columns:
        emp["r_and_d_FTEs"] = emp["rd_FTEs"]

    # Ensure numeric fields (missing => 0)
    emp = _ensure_numeric(emp, [
        "admin_FTEs",
        "service_production_FTEs",
        "legal_FTEs",
        "r_and_d_FTEs",
        "sales_mkt_FTEs",
    ], default=0.0)

    return emp


def normalize_sites(sites: pd.DataFrame) -> pd.DataFrame:
    if sites is None or sites.empty:
        return pd.DataFrame(columns=["cons_unit", "country", "site_name"])

    sites = _clean_cols(sites)
    ensure_cols(sites, ["cons_unit"], "production_sites")
    sites = _norm_cons_unit(_norm_country(sites))

    if "site_name" not in sites.columns:
        # try common alternatives
        for alt in ["facility_name", "plant_name", "location_name"]:
            if alt in sites.columns:
                sites["site_name"] = sites[alt]
                break
        if "site_name" not in sites.columns:
            sites["site_name"] = ""

    if "country" not in sites.columns:
        sites["country"] = ""

    return sites


# =========================
# Core checks (rules)
# =========================
def run_rules(
    cu: pd.DataFrame,
    leases: pd.DataFrame,
    emp: pd.DataFrame,
    sites: pd.DataFrame
) -> List[Issue]:
    """
    Returns a list[Issue]. It should NEVER crash for optional missing datasets/columns.
    It will only error if consolidation_units lacks required minimal columns.
    """
    cu_n = normalize_consolidation_units(cu)
    leases_n = normalize_leases(leases)
    emp_n = normalize_employees(emp)
    sites_n = normalize_sites(sites)

    issues: List[Issue] = []

    cu_set = set(cu_n["cons_unit"].astype(str))

    # ---------- Rule CU_001: duplicate cons_unit in master ----------
    dup = cu_n["cons_unit"].astype(str).duplicated(keep=False)
    if dup.any():
        dups = cu_n.loc[dup, ["cons_unit", "country", "company_name"]]
        for _, r in dups.iterrows():
            issues.append(_issue(
                severity="HIGH",
                rule_id="CU_001",
                title="Duplicate cons_unit in consolidation_units",
                cons_unit=r.get("cons_unit", ""),
                dataset="consolidation_units",
                record_id=r.get("cons_unit", ""),
                country=r.get("country", ""),
                details=f"cons_unit '{r.get('cons_unit','')}' appears multiple times in consolidation_units.",
                suggested_action="Deduplicate consolidation master or clarify consolidation mapping."
            ))

    # ---------- Rule DS_001: dataset cons_unit not in master ----------
    def _missing_in_master(df: pd.DataFrame, dataset_name: str, id_col: str = ""):
        if df is None or df.empty or "cons_unit" not in df.columns:
            return
        unknown = sorted(set(df["cons_unit"].astype(str)) - cu_set)
        for u in unknown:
            issues.append(_issue(
                severity="HIGH",
                rule_id="DS_001",
                title="cons_unit not found in consolidation_units",
                cons_unit=u,
                dataset=dataset_name,
                record_id=u,
                country="",
                details=f"'{u}' appears in {dataset_name} but not in consolidation_units.",
                suggested_action="Fix upstream extract or add missing consolidation unit to master."
            ))

    _missing_in_master(leases_n, "leases")
    _missing_in_master(emp_n, "employees")
    _missing_in_master(sites_n, "production_sites")

    # ---------- Rule COV_001: master cons_unit with no signals anywhere ----------
    # "Signals" means appears in any dataset. Holding entities may legitimately have none,
    # so severity is MEDIUM (review) rather than HIGH.
    signals = set()
    for df in [leases_n, emp_n, sites_n]:
        if df is not None and not df.empty and "cons_unit" in df.columns:
            signals |= set(df["cons_unit"].astype(str))

    for cu_code in sorted(cu_set):
        if cu_code not in signals:
            country = cu_n.loc[cu_n["cons_unit"].astype(str) == cu_code, "country"]
            company = cu_n.loc[cu_n["cons_unit"].astype(str) == cu_code, "company_name"]
            issues.append(_issue(
                severity="MEDIUM",
                rule_id="COV_001",
                title="No operational signals for cons_unit",
                cons_unit=cu_code,
                dataset="consolidation_units",
                record_id=cu_code,
                country=str(country.iloc[0]) if len(country) else "",
                details=f"'{cu_code}' has no matching records in leases/employees/sites. Could be holding/dormant entity or missing data.",
                suggested_action="Confirm if holding/dormant; otherwise investigate missing extracts."
            ))

    # ---------- Rule EMP_001: employees record exists but all FTEs = 0 ----------
    if emp_n is not None and not emp_n.empty:
        fte_cols = ["admin_FTEs", "service_production_FTEs", "legal_FTEs", "r_and_d_FTEs", "sales_mkt_FTEs"]
        emp_n = _ensure_numeric(emp_n, fte_cols, default=0.0)
        emp_n["fte_total"] = emp_n[fte_cols].sum(axis=1)

        zero = emp_n["fte_total"] <= 0
        for _, r in emp_n.loc[zero].iterrows():
            issues.append(_issue(
                severity="LOW",
                rule_id="EMP_001",
                title="Employees row with zero total FTE",
                cons_unit=r.get("cons_unit", ""),
                dataset="employees",
                record_id=r.get("cons_unit", ""),
                country="",
                details="Employees record exists but total FTE is 0. This can indicate incomplete HR extract.",
                suggested_action="Confirm HR data extract; remove empty rows or provide correct FTE split."
            ))

    # ---------- Rule LEASE_001: lease missing facility_type ----------
    if leases_n is not None and not leases_n.empty:
        missing_type = leases_n["facility_type"].astype(str).fillna("").str.strip().eq("")
        for idx, r in leases_n.loc[missing_type].iterrows():
            issues.append(_issue(
                severity="LOW",
                rule_id="LEASE_001",
                title="Lease missing facility type",
                cons_unit=r.get("cons_unit", ""),
                dataset="leases",
                record_id=r.get("contract_name", f"row_{idx}"),
                country=r.get("country", ""),
                details="Lease has no facility_type. Facility classification is needed for ESG scoping (office/warehouse/production/etc.).",
                suggested_action="Add facility_type in lease extract or mapping layer."
            ))

    # ---------- Rule SITE_001: production site missing site_name ----------
    if sites_n is not None and not sites_n.empty:
        missing_name = sites_n["site_name"].astype(str).fillna("").str.strip().eq("")
        for idx, r in sites_n.loc[missing_name].iterrows():
            issues.append(_issue(
                severity="LOW",
                rule_id="SITE_001",
                title="Production site missing site name",
                cons_unit=r.get("cons_unit", ""),
                dataset="production_sites",
                record_id=f"row_{idx}",
                country=r.get("country", ""),
                details="Site record has no site_name; this reduces auditability and completeness checks.",
                suggested_action="Provide site_name/facility_name in the source extract."
            ))

    return issues


# =========================
# Outputs for UI
# =========================
def issues_to_frames(issues: List[Issue]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Returns:
      issues_df: normalized issue table
      summary_df: aggregated counts by severity and dataset
    """
    if not issues:
        issues_df = pd.DataFrame(columns=[
            "severity", "rule_id", "title", "cons_unit", "dataset", "record_id", "country", "details", "suggested_action"
        ])
        summary_df = pd.DataFrame(columns=["severity", "dataset", "count"])
        return issues_df, summary_df

    issues_df = pd.DataFrame([asdict(i) for i in issues])

    summary_df = (
        issues_df.groupby(["severity", "dataset"], dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values(["severity", "dataset"])
    )

    return issues_df, summary_df


def compute_coverage(cu: pd.DataFrame, df: pd.DataFrame) -> Dict[str, int]:
    """
    Coverage computed by cons_unit matching.
    Returns: {master_total, matched, unknown}
    """
    cu_n = normalize_consolidation_units(cu)
    master = set(cu_n["cons_unit"].astype(str))

    if df is None or df.empty or "cons_unit" not in df.columns:
        return {"master_total": len(master), "matched": 0, "unknown": 0}

    df = _norm_cons_unit(_clean_cols(df))
    units = set(df["cons_unit"].astype(str))
    matched = len(units & master)
    unknown = len(units - master)

    return {"master_total": len(master), "matched": matched, "unknown": unknown}


def compute_coverage_matrix(cu: pd.DataFrame, leases: pd.DataFrame, emp: pd.DataFrame, sites: pd.DataFrame) -> pd.DataFrame:
    """
    One row per master cons_unit, columns indicate whether a dataset has at least one record.
    """
    cu_n = normalize_consolidation_units(cu)
    leases_n = normalize_leases(leases)
    emp_n = normalize_employees(emp)
    sites_n = normalize_sites(sites)

    master = sorted(set(cu_n["cons_unit"].astype(str)))

    def has(df: pd.DataFrame) -> set:
        if df is None or df.empty or "cons_unit" not in df.columns:
            return set()
        return set(df["cons_unit"].astype(str))

    s_leases = has(leases_n)
    s_emp = has(emp_n)
    s_sites = has(sites_n)

    out = pd.DataFrame({
        "cons_unit": master,
        "in_leases": [cu in s_leases for cu in master],
        "in_employees": [cu in s_emp for cu in master],
        "in_sites": [cu in s_sites for cu in master],
    })

    # Add company + country for convenience
    meta = cu_n[["cons_unit", "country", "company_name"]].copy()
    meta["cons_unit"] = meta["cons_unit"].astype(str)
    out = out.merge(meta, on="cons_unit", how="left")

    # coverage score
    out["datasets_present"] = out[["in_leases", "in_employees", "in_sites"]].sum(axis=1)
    return out


def compute_risk_score(issues_df: pd.DataFrame, coverage: Dict[str, Dict[str, int]]) -> float:
    """
    Simple heuristic:
    - Issues severity weights: HIGH=10, MEDIUM=5, LOW=1
    - Coverage penalty: missing matches reduce score
    Output 0..100 (higher = worse)
    """
    if issues_df is None or issues_df.empty:
        issue_points = 0.0
    else:
        sev = issues_df["severity"].astype(str).str.upper()
        issue_points = (
            (sev == "HIGH").sum() * 10.0 +
            (sev == "MEDIUM").sum() * 5.0 +
            (sev == "LOW").sum() * 1.0
        )

    # Coverage penalty based on matched ratio
    cov_points = 0.0
    for k, v in (coverage or {}).items():
        master_total = max(int(v.get("master_total", 0)), 1)
        matched = int(v.get("matched", 0))
        ratio = matched / master_total
        # missing coverage adds points
        cov_points += (1.0 - ratio) * 10.0

    score = issue_points + cov_points

    # normalize to 0..100 with a soft cap
    score = min(100.0, float(score))
    return score


def diff_runs(prev_matrix: pd.DataFrame, curr_matrix: pd.DataFrame) -> pd.DataFrame:
    """
    Compare two coverage_matrix tables (from compute_coverage_matrix).
    Returns rows where any dataset flags changed.
    """
    if prev_matrix is None or prev_matrix.empty:
        return pd.DataFrame(columns=["cons_unit", "field", "prev", "curr"])
    if curr_matrix is None or curr_matrix.empty:
        return pd.DataFrame(columns=["cons_unit", "field", "prev", "curr"])

    prev = prev_matrix.copy()
    curr = curr_matrix.copy()

    # ensure required columns exist
    for df in [prev, curr]:
        if "cons_unit" not in df.columns:
            raise ValueError("coverage_matrix must include cons_unit")

    prev["cons_unit"] = prev["cons_unit"].astype(str)
    curr["cons_unit"] = curr["cons_unit"].astype(str)

    keys = ["cons_unit"]
    fields = [c for c in ["in_leases", "in_employees", "in_sites", "datasets_present"] if c in prev.columns and c in curr.columns]

    merged = prev[keys + fields].merge(curr[keys + fields], on="cons_unit", how="outer", suffixes=("_prev", "_curr")).fillna(False)

    changes = []
    for _, r in merged.iterrows():
        cu = r["cons_unit"]
        for f in fields:
            pv = r.get(f + "_prev", False)
            cv = r.get(f + "_curr", False)
            if pv != cv:
                changes.append({"cons_unit": cu, "field": f, "prev": pv, "curr": cv})

    return pd.DataFrame(changes)


# Optional: if other parts of your app still call these
def read_workbook(path: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Legacy helper: reads sheets with standard names if present.
    Your new app uses its own raw reader + mapping UI, so this is here for backward compatibility.
    """
    xls = pd.ExcelFile(path)
    def rs(name: str) -> pd.DataFrame:
        if name in xls.sheet_names:
            return pd.read_excel(xls, sheet_name=name)
        return pd.DataFrame()

    cu = rs("consolidation_units")
    leases = rs("leases")
    emp = rs("employees")
    sites = rs("production_sites")
    return cu, leases, emp, sites