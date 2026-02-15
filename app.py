import os
import json
import tempfile
import hashlib
from datetime import datetime

import pandas as pd
import streamlit as st
import bcrypt  # bcrypt library (NOT passlib)

from db import get_engine, exec_sql, fetch_all, fetch_one
from maptrix_engine import (
    run_rules,
    issues_to_frames,
    compute_coverage,
    compute_coverage_matrix,
    compute_risk_score,
    apply_mappings,
    diff_runs,
)

st.set_page_config(page_title="Maptrix", layout="wide")

ENGINE = get_engine()

# =========================
# DB bootstrap (SQLite dev)
# =========================
def bootstrap_sqlite():
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    """,
    )
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      reporting_date TEXT NULL,
      filename TEXT NULL,
      master_units INTEGER NOT NULL DEFAULT 0,
      issues_count INTEGER NOT NULL DEFAULT 0,
      risk_score REAL NOT NULL DEFAULT 0
    );
    """,
    )
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS run_tables (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id INTEGER NOT NULL,
      table_name TEXT NOT NULL,
      data_json TEXT NOT NULL
    );
    """,
    )
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS run_issues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id INTEGER NOT NULL,
      severity TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      title TEXT NOT NULL,
      cons_unit TEXT NOT NULL,
      dataset TEXT NOT NULL,
      record_id TEXT NOT NULL,
      country TEXT NOT NULL,
      details TEXT NOT NULL,
      suggested_action TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'OPEN',
      owner TEXT NULL,
      created_at TEXT NOT NULL
    );
    """,
    )
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS issue_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      issue_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      comment TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    """,
    )
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS cons_unit_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      from_cons_unit TEXT NOT NULL,
      to_cons_unit TEXT NOT NULL,
      note TEXT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(user_id, from_cons_unit)
    );
    """,
    )
    # Column-mapping templates (so users don't remap every quarter)
    exec_sql(
        ENGINE,
        """
    CREATE TABLE IF NOT EXISTS column_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      template_name TEXT NOT NULL,
      mapping_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(user_id, template_name)
    );
    """,
    )


bootstrap_sqlite()

# =========================
# Auth (bcrypt + sha256 prehash)
# =========================
def get_user_by_email(email: str):
    return fetch_one(ENGINE, "SELECT * FROM users WHERE email=:e", {"e": email})


def _pw_bytes(password: str) -> bytes:
    # avoids bcrypt 72-byte limit by hashing to fixed length
    return hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")


def create_user(email: str, password: str):
    email = email.strip().lower()
    if get_user_by_email(email):
        raise ValueError("This email already exists. Please login instead.")
    hashed = bcrypt.hashpw(_pw_bytes(password), bcrypt.gensalt()).decode("utf-8")
    exec_sql(
        ENGINE,
        "INSERT INTO users(email,password_hash,created_at) VALUES(:e,:p,:t)",
        {"e": email, "p": hashed, "t": datetime.utcnow().isoformat()},
    )


def verify_user(email: str, password: str):
    email = email.strip().lower()
    u = get_user_by_email(email)
    if not u:
        return None
    stored = str(u["password_hash"]).encode("utf-8")
    if bcrypt.checkpw(_pw_bytes(password), stored):
        return u
    return None


def require_login():
    if "user" not in st.session_state:
        st.session_state.user = None

    if st.session_state.user:
        return st.session_state.user

    st.title("Maptrix")
    st.caption("Login to continue.")
    tab1, tab2 = st.tabs(["Login", "Create account"])

    with tab1:
        email = st.text_input("Email", key="login_email")
        pw = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login"):
            u = verify_user(email, pw)
            if u:
                st.session_state.user = dict(u)
                st.rerun()
            else:
                st.error("Invalid credentials.")

    with tab2:
        email = st.text_input("Email", key="signup_email")
        pw = st.text_input("Password", type="password", key="signup_pw")
        if st.button("Create account"):
            try:
                create_user(email, pw)
                st.success("Account created. Please login.")
            except Exception as e:
                st.error(f"Could not create account: {e}")

    st.stop()


user = require_login()
user_id = int(user["id"])

# =========================
# Helpers: workbook + normalization
# =========================
def read_workbook_raw(path: str) -> dict[str, pd.DataFrame]:
    xls = pd.ExcelFile(path)
    out: dict[str, pd.DataFrame] = {}
    for sheet in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet)
        df.columns = [str(c).strip() for c in df.columns]
        out[sheet] = df
    return out


def df_to_json(df: pd.DataFrame) -> str:
    return df.to_json(orient="records")


def json_to_df(s: str) -> pd.DataFrame:
    return pd.DataFrame(json.loads(s)) if s else pd.DataFrame()


def apply_column_mapping(df: pd.DataFrame, mapping: dict[str, str], derive: dict[str, str]) -> pd.DataFrame:
    """
    mapping: canonical_field -> uploaded_column_name
    derive: target_canonical_field -> source_canonical_field (post-rename)
    """
    out = df.copy()
    rename_map = {uploaded: canon for canon, uploaded in mapping.items() if uploaded and uploaded != "(none)"}
    out = out.rename(columns=rename_map)

    # derive optional fields
    for target, source in derive.items():
        if target not in out.columns and source in out.columns:
            out[target] = out[source]

    # tidy common fields
    if "cons_unit" in out.columns:
        out["cons_unit"] = out["cons_unit"].astype(str).str.strip()
    if "country" in out.columns:
        out["country"] = out["country"].astype(str).str.strip()

    return out


def validate_required(df: pd.DataFrame, required: list[str], sheet: str) -> list[str]:
    missing = [c for c in required if c not in df.columns]
    return [f"{sheet}: missing required field '{c}'" for c in missing]


def normalize_colname(s: str) -> str:
    return "".join(ch.lower() for ch in str(s).strip() if ch.isalnum())


def autosuggest_mapping(df: pd.DataFrame, canonical_fields: list[str]) -> dict[str, str]:
    """
    Simple auto-suggest: matches normalized column names against normalized canonical names
    and common alias patterns.
    """
    cols = list(df.columns)
    norm_to_col = {normalize_colname(c): c for c in cols}

    aliases = {
        "cons_unit": ["consunit", "consolidationunit", "consolidationunits", "consunitcode", "unitcode", "consolidationunitcode"],
        "company_name": ["company", "companyname", "legalentity", "legalentityname", "entityname", "legalentity_name"],
        "cons_unit_name": ["consunitname", "unitname", "consolidationunitname"],
        "company_code": ["companycode", "entitycode", "code"],
        "contract_name": ["contract", "contractname", "leasecontract", "leasecontractname"],
        "start_date": ["startdate", "leasestart", "commencementdate", "start"],
        "end_date": ["enddate", "leaseend", "expirydate", "end"],
        "facility_type": ["facilitytype", "sitetype", "buildingtype", "type"],
        "site_name": ["sitename", "locationname", "plantname", "facilityname", "site"],
    }

    suggested: dict[str, str] = {}
    for f in canonical_fields:
        # exact canonical
        cand = norm_to_col.get(normalize_colname(f))
        if cand:
            suggested[f] = cand
            continue
        # alias match
        for a in aliases.get(f, []):
            cand = norm_to_col.get(a)
            if cand:
                suggested[f] = cand
                break

    return suggested


# =========================
# Domain-specific canonical schema
# =========================
CANONICAL = {
    "consolidation_units": {
        "required": ["cons_unit", "country", "company_name"],
        "optional": ["cons_unit_name"],
        "derive": {"cons_unit_name": "company_name"},
    },
    "leases": {
        "required": ["cons_unit"],
        "optional": ["country", "company_code", "contract_name", "start_date", "end_date", "facility_type"],
        "derive": {},
    },
    "employees": {
        "required": ["cons_unit"],
        "optional": ["unit_name", "admin_FTEs", "service_production_FTEs", "legal_FTEs", "rd_FTEs", "sales_mkt_FTEs"],
        "derive": {},
    },
    "production_sites": {
        "required": ["cons_unit"],
        "optional": ["country", "site_name"],
        "derive": {},
    },
}

# =========================
# Persistence: cons_unit mapping memory
# =========================
def load_mappings(user_id: int) -> dict:
    rows = fetch_all(
        ENGINE,
        "SELECT from_cons_unit, to_cons_unit FROM cons_unit_mappings WHERE user_id=:u",
        {"u": user_id},
    )
    return {r["from_cons_unit"]: r["to_cons_unit"] for r in rows}


def upsert_mapping(user_id: int, from_cu: str, to_cu: str, note: str = ""):
    exec_sql(ENGINE, "DELETE FROM cons_unit_mappings WHERE user_id=:u AND from_cons_unit=:f", {"u": user_id, "f": from_cu})
    exec_sql(
        ENGINE,
        """
      INSERT INTO cons_unit_mappings(user_id, from_cons_unit, to_cons_unit, note, created_at)
      VALUES(:u,:f,:t,:n,:c)
    """,
        {"u": user_id, "f": from_cu, "t": to_cu, "n": note, "c": datetime.utcnow().isoformat()},
    )

# =========================
# Persistence: column templates
# =========================
def list_templates(user_id: int) -> list[dict]:
    return fetch_all(
        ENGINE,
        "SELECT template_name, created_at FROM column_templates WHERE user_id=:u ORDER BY template_name",
        {"u": user_id},
    )

def load_template(user_id: int, template_name: str) -> dict:
    row = fetch_one(
        ENGINE,
        "SELECT mapping_json FROM column_templates WHERE user_id=:u AND template_name=:t",
        {"u": user_id, "t": template_name},
    )
    return json.loads(row["mapping_json"]) if row else {}

def save_template(user_id: int, template_name: str, mapping: dict):
    template_name = template_name.strip()
    if not template_name:
        raise ValueError("Template name cannot be empty.")
    exec_sql(
        ENGINE,
        "DELETE FROM column_templates WHERE user_id=:u AND template_name=:t",
        {"u": user_id, "t": template_name},
    )
    exec_sql(
        ENGINE,
        """
        INSERT INTO column_templates(user_id, template_name, mapping_json, created_at)
        VALUES(:u,:t,:j,:c)
        """,
        {"u": user_id, "t": template_name, "j": json.dumps(mapping), "c": datetime.utcnow().isoformat()},
    )

# =========================
# Persistence: runs + issues + comments
# =========================
def save_run(user_id: int, filename: str, reporting_date: str, tables: dict, issues_df: pd.DataFrame, risk_score: float, master_units: int):
    exec_sql(
        ENGINE,
        """
      INSERT INTO runs(user_id, created_at, reporting_date, filename, master_units, issues_count, risk_score)
      VALUES(:u,:t,:r,:f,:m,:i,:s)
    """,
        {
            "u": user_id,
            "t": datetime.utcnow().isoformat(),
            "r": reporting_date or None,
            "f": filename,
            "m": master_units,
            "i": int(len(issues_df)),
            "s": float(risk_score),
        },
    )
    run_row = fetch_one(ENGINE, "SELECT id FROM runs WHERE user_id=:u ORDER BY id DESC LIMIT 1", {"u": user_id})
    run_id = int(run_row["id"])

    for name, df in tables.items():
        exec_sql(ENGINE, "INSERT INTO run_tables(run_id, table_name, data_json) VALUES(:r,:n,:j)", {"r": run_id, "n": name, "j": df_to_json(df)})

    for _, r in issues_df.iterrows():
        exec_sql(
            ENGINE,
            """
          INSERT INTO run_issues(run_id,severity,rule_id,title,cons_unit,dataset,record_id,country,details,suggested_action,status,owner,created_at)
          VALUES(:run,:sev,:rid,:title,:cu,:ds,:rec,:cty,:det,:act,'OPEN',NULL,:t)
        """,
            {
                "run": run_id,
                "sev": r.get("severity", ""),
                "rid": r.get("rule_id", ""),
                "title": r.get("title", ""),
                "cu": r.get("cons_unit", ""),
                "ds": r.get("dataset", ""),
                "rec": r.get("record_id", ""),
                "cty": r.get("country", ""),
                "det": r.get("details", ""),
                "act": r.get("suggested_action", ""),
                "t": datetime.utcnow().isoformat(),
            },
        )

    return run_id

def list_runs(user_id: int):
    return fetch_all(ENGINE, "SELECT * FROM runs WHERE user_id=:u ORDER BY id DESC", {"u": user_id})

def load_run_table(run_id: int, table_name: str) -> pd.DataFrame:
    row = fetch_one(ENGINE, "SELECT data_json FROM run_tables WHERE run_id=:r AND table_name=:n", {"r": run_id, "n": table_name})
    if not row:
        return pd.DataFrame()
    return json_to_df(row["data_json"])

def load_run_issues(run_id: int) -> pd.DataFrame:
    rows = fetch_all(ENGINE, "SELECT * FROM run_issues WHERE run_id=:r ORDER BY id DESC", {"r": run_id})
    return pd.DataFrame(rows)

def update_issue_status(issue_id: int, status: str, owner: str = ""):
    exec_sql(ENGINE, "UPDATE run_issues SET status=:s, owner=:o WHERE id=:i", {"s": status, "o": owner or None, "i": int(issue_id)})

def add_comment(issue_id: int, user_id: int, comment: str):
    exec_sql(
        ENGINE,
        "INSERT INTO issue_comments(issue_id,user_id,comment,created_at) VALUES(:i,:u,:c,:t)",
        {"i": int(issue_id), "u": int(user_id), "c": comment, "t": datetime.utcnow().isoformat()},
    )

def load_comments(issue_id: int):
    return fetch_all(ENGINE, "SELECT * FROM issue_comments WHERE issue_id=:i ORDER BY id DESC", {"i": int(issue_id)})

# =========================
# UI
# =========================
st.sidebar.header("Maptrix")
st.sidebar.caption("build: 2026-02-15 mapping-step")
st.sidebar.caption(f"Logged in as {user['email']}")

if st.sidebar.button("Logout"):
    st.session_state.user = None
    st.rerun()

page = st.sidebar.radio("Navigate", ["Upload → Map → Run", "Run History", "cons_unit Mappings", "Issues Workflow", "Column Templates"])

cons_unit_mappings = load_mappings(user_id)

# -----------------------------------
# PAGE: Upload → Map → Run
# -----------------------------------
if page == "Upload → Map → Run":
    st.title("Upload → Map → Run")
    st.caption("Commercial flow: Upload workbook → Map columns → Preview → Run checks → Save run")

    reporting_date = st.date_input("Reporting date (optional)", value=None)
    uploaded = st.file_uploader("Upload Excel (.xlsx)", type=["xlsx"])

    if not uploaded:
        st.info("Upload a workbook to begin.")
        st.stop()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = tmp.name

    try:
        raw = read_workbook_raw(tmp_path)

        # Canonical sheets required/optional (by our product)
        # We allow customers to upload with different sheet names by letting them choose which sheet maps to each dataset.
        st.subheader("Step 0 — Choose which sheet is which dataset")
        sheet_names = list(raw.keys())
        if "sheet_bindings" not in st.session_state:
            st.session_state.sheet_bindings = {}

        # Default bindings if exact names exist
        defaults = {
            "consolidation_units": "consolidation_units" if "consolidation_units" in sheet_names else (sheet_names[0] if sheet_names else ""),
            "leases": "leases" if "leases" in sheet_names else "",
            "employees": "employees" if "employees" in sheet_names else "",
            "production_sites": "production_sites" if "production_sites" in sheet_names else "",
        }

        bindings = st.session_state.sheet_bindings
        for dataset in ["consolidation_units", "leases", "employees", "production_sites"]:
            opts = ["(none)"] + sheet_names
            default = bindings.get(dataset, defaults.get(dataset, "(none)"))
            bindings[dataset] = st.selectbox(
                f"{dataset} sheet",
                opts,
                index=opts.index(default) if default in opts else 0,
                key=f"bind_{dataset}",
                help="Pick which uploaded sheet corresponds to this dataset.",
            )
        st.session_state.sheet_bindings = bindings

        if bindings["consolidation_units"] == "(none)":
            st.error("You must select a sheet for consolidation_units.")
            st.stop()

        # Create raw dfs per dataset
        dataset_raw: dict[str, pd.DataFrame] = {}
        for dataset, sheet in bindings.items():
            if sheet and sheet != "(none)":
                dataset_raw[dataset] = raw[sheet].copy()

        st.divider()
        st.subheader("Step 1 — Map columns to Maptrix fields")

        # template load
        templates = list_templates(user_id)
        template_names = ["(none)"] + [t["template_name"] for t in templates]
        chosen_template = st.selectbox("Load a saved column-mapping template (optional)", template_names, index=0)
        if st.button("Load template"):
            if chosen_template != "(none)":
                st.session_state.column_mapping = load_template(user_id, chosen_template)
                st.success(f"Loaded template: {chosen_template}")
                st.rerun()

        if "column_mapping" not in st.session_state or not isinstance(st.session_state.column_mapping, dict):
            st.session_state.column_mapping = {}

        errors: list[str] = []

        # Map each dataset
        for dataset, schema in CANONICAL.items():
            if dataset not in dataset_raw:
                st.warning(f"{dataset}: no sheet selected (optional).")
                continue

            df = dataset_raw[dataset]
            cols = ["(none)"] + list(df.columns)

            # init mapping dict for dataset
            if dataset not in st.session_state.column_mapping:
                st.session_state.column_mapping[dataset] = {}

            # auto-suggest button per dataset
            with st.expander(f"Map columns for: {dataset}", expanded=(dataset == "consolidation_units")):
                c1, c2, _ = st.columns([1, 1, 2])
                if c1.button("Auto-suggest", key=f"autosuggest_{dataset}"):
                    suggested = autosuggest_mapping(df, schema["required"] + schema["optional"])
                    # apply suggestions without deleting user's existing choices
                    for k, v in suggested.items():
                        if st.session_state.column_mapping[dataset].get(k, "(none)") in ["", "(none)"]:
                            st.session_state.column_mapping[dataset][k] = v
                    st.rerun()

                st.markdown("**Required**")
                for canon in schema["required"]:
                    default = st.session_state.column_mapping[dataset].get(canon, "(none)")
                    st.session_state.column_mapping[dataset][canon] = st.selectbox(
                        f"{canon}",
                        cols,
                        index=cols.index(default) if default in cols else 0,
                        key=f"map_{dataset}_{canon}",
                    )

                st.markdown("**Optional**")
                for canon in schema["optional"]:
                    default = st.session_state.column_mapping[dataset].get(canon, "(none)")
                    st.session_state.column_mapping[dataset][canon] = st.selectbox(
                        f"{canon}",
                        cols,
                        index=cols.index(default) if default in cols else 0,
                        key=f"map_{dataset}_{canon}",
                    )

                preview = apply_column_mapping(df, st.session_state.column_mapping[dataset], schema["derive"])
                st.caption("Preview (normalized) — first 20 rows")
                st.dataframe(preview.head(20), use_container_width=True)

        # Build normalized dfs
        normalized: dict[str, pd.DataFrame] = {}
        for dataset, schema in CANONICAL.items():
            if dataset in dataset_raw:
                normalized[dataset] = apply_column_mapping(dataset_raw[dataset], st.session_state.column_mapping.get(dataset, {}), schema["derive"])

        # Validation
        errors += validate_required(normalized["consolidation_units"], CANONICAL["consolidation_units"]["required"], "consolidation_units")
        for dataset in ["leases", "employees", "production_sites"]:
            if dataset in normalized:
                errors += validate_required(normalized[dataset], CANONICAL[dataset]["required"], dataset)

        # Show save template control
        st.divider()
        st.subheader("Save mapping template (optional)")
        template_name = st.text_input("Template name", value="")
        if st.button("Save template"):
            try:
                save_template(user_id, template_name, st.session_state.column_mapping)
                st.success(f"Saved template: {template_name}")
            except Exception as e:
                st.error(f"Could not save template: {e}")

        st.divider()
        st.subheader("Step 2 — Run checks")
        if errors:
            st.error("Fix these before running:")
            for e in errors:
                st.write(f"- {e}")
            st.stop()

        if st.button("Run Maptrix checks"):
            cu = normalized.get("consolidation_units", pd.DataFrame())
            leases = normalized.get("leases", pd.DataFrame())
            emp = normalized.get("employees", pd.DataFrame())
            sites = normalized.get("production_sites", pd.DataFrame())

            # Apply cons_unit mapping memory BEFORE checks
            leases = apply_mappings(leases, cons_unit_mappings)
            emp = apply_mappings(emp, cons_unit_mappings)
            sites = apply_mappings(sites, cons_unit_mappings)

            # Coverage
            cov = {
                "leases": compute_coverage(cu, leases),
                "employees": compute_coverage(cu, emp),
                "sites": compute_coverage(cu, sites),
            }

            issues = run_rules(cu, leases, emp, sites)
            issues_df, summary_df = issues_to_frames(issues)
            risk = compute_risk_score(issues_df, cov)
            master_units = len(set(cu["cons_unit"].astype(str)))

            st.success("Checks completed.")

            k1, k2, k3 = st.columns(3)
            k1.metric("Issues", len(issues_df))
            k2.metric("Risk score (0-100)", f"{risk:.1f}")
            k3.metric("Master cons_units", master_units)

            st.subheader("Coverage Matrix")
            cov_matrix = compute_coverage_matrix(cu, leases, emp, sites)
            st.dataframe(cov_matrix, use_container_width=True)

            st.subheader("Summary")
            st.dataframe(summary_df, use_container_width=True)

            st.subheader("Issues")
            st.dataframe(issues_df, use_container_width=True)

            st.divider()
            if st.button("Save this run"):
                tables = {
                    "consolidation_units": cu,
                    "leases": leases,
                    "employees": emp,
                    "production_sites": sites,
                    "coverage_matrix": cov_matrix,
                    "issues": issues_df,
                    "summary": summary_df,
                }
                run_id = save_run(
                    user_id=user_id,
                    filename=uploaded.name,
                    reporting_date=str(reporting_date) if reporting_date else "",
                    tables=tables,
                    issues_df=issues_df,
                    risk_score=risk,
                    master_units=master_units,
                )
                st.success(f"Saved run #{run_id}. Go to Run History to compare.")

    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

# -----------------------------------
# PAGE: Run History
# -----------------------------------
elif page == "Run History":
    st.title("Run History")
    runs = list_runs(user_id)
    if not runs:
        st.info("No saved runs yet.")
        st.stop()

    run_options = {
        f"Run #{r['id']} — {str(r.get('created_at',''))[:19]} — risk {float(r.get('risk_score',0)):.1f}": int(r["id"])
        for r in runs
    }
    sel = st.selectbox("Select run", list(run_options.keys()))
    run_id = run_options[sel]

    tabs = st.tabs(["Coverage Matrix", "Issues", "Summary", "Leases", "Employees", "Sites"])
    with tabs[0]:
        st.dataframe(load_run_table(run_id, "coverage_matrix"), use_container_width=True)
    with tabs[1]:
        st.dataframe(load_run_issues(run_id), use_container_width=True)
    with tabs[2]:
        st.dataframe(load_run_table(run_id, "summary"), use_container_width=True)
    with tabs[3]:
        st.dataframe(load_run_table(run_id, "leases"), use_container_width=True)
    with tabs[4]:
        st.dataframe(load_run_table(run_id, "employees"), use_container_width=True)
    with tabs[5]:
        st.dataframe(load_run_table(run_id, "production_sites"), use_container_width=True)

    st.divider()
    st.subheader("Compare with previous run")
    if len(runs) >= 2:
        prev_run_id = int(runs[1]["id"]) if int(runs[0]["id"]) == run_id else int(runs[0]["id"])
        prev_matrix = load_run_table(prev_run_id, "coverage_matrix")
        curr_matrix = load_run_table(run_id, "coverage_matrix")
        changes = diff_runs(prev_matrix, curr_matrix)
        st.dataframe(changes, use_container_width=True)
    else:
        st.info("Need at least 2 runs to compare.")

# -----------------------------------
# PAGE: cons_unit Mappings
# -----------------------------------
elif page == "cons_unit Mappings":
    st.title("cons_unit Mappings (memory)")
    st.caption("Use this when your source systems use different cons_unit codes than your consolidation extract.")

    rows = fetch_all(ENGINE, "SELECT * FROM cons_unit_mappings WHERE user_id=:u ORDER BY id DESC", {"u": user_id})
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    st.subheader("Add / update mapping")
    from_cu = st.text_input("From cons_unit (unknown)", "")
    to_cu = st.text_input("To cons_unit (canonical)", "")
    note = st.text_input("Note (optional)", "")
    if st.button("Save cons_unit mapping"):
        if not from_cu.strip() or not to_cu.strip():
            st.error("Both From and To are required.")
        else:
            upsert_mapping(user_id, from_cu.strip(), to_cu.strip(), note.strip())
            st.success("Saved mapping.")
            st.rerun()

# -----------------------------------
# PAGE: Issues Workflow
# -----------------------------------
elif page == "Issues Workflow":
    st.title("Issues Workflow")

    runs = list_runs(user_id)
    if not runs:
        st.info("No runs saved yet.")
        st.stop()

    run_id = st.selectbox("Select run", [int(r["id"]) for r in runs])
    issues_df = load_run_issues(run_id)
    if issues_df.empty:
        st.info("No issues for this run.")
        st.stop()

    st.subheader("Issues list")
    st.dataframe(
        issues_df[["id", "severity", "rule_id", "title", "cons_unit", "dataset", "status", "owner"]],
        use_container_width=True,
    )

    st.subheader("Update an issue")
    issue_id = st.number_input("Issue ID", min_value=1, step=1)
    status = st.selectbox("Status", ["OPEN", "IN_REVIEW", "RESOLVED", "DISMISSED"])
    owner = st.text_input("Owner (optional)", "")
    if st.button("Update issue"):
        update_issue_status(int(issue_id), status, owner)
        st.success("Updated.")
        st.rerun()

    st.subheader("Comments")
    comment = st.text_area("Add a comment", "")
    if st.button("Post comment"):
        if not comment.strip():
            st.error("Comment cannot be empty.")
        else:
            add_comment(int(issue_id), user_id, comment.strip())
            st.success("Comment added.")
            st.rerun()

    st.caption("Latest comments")
    comments = load_comments(int(issue_id))
    if comments:
        for c in comments:
            st.write(f"- {str(c.get('created_at',''))[:19]}: {c.get('comment','')}")
    else:
        st.write("No comments yet.")

# -----------------------------------
# PAGE: Column Templates
# -----------------------------------
elif page == "Column Templates":
    st.title("Column Mapping Templates")
    st.caption("Saved templates let you map once and reuse each quarter.")

    templates = list_templates(user_id)
    if not templates:
        st.info("No templates saved yet. Save one from the Upload → Map → Run page.")
        st.stop()

    st.dataframe(pd.DataFrame(templates), use_container_width=True)

    to_load = st.selectbox("Load template", [t["template_name"] for t in templates])
    if st.button("Load into current session"):
        st.session_state.column_mapping = load_template(user_id, to_load)
        st.success(f"Loaded template into session: {to_load}")