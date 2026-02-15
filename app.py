import os
import json
import tempfile
import hashlib
from datetime import datetime

import pandas as pd
import streamlit as st
from passlib.hash import bcrypt

from db import get_engine, exec_sql, fetch_all, fetch_one
from maptrix_engine import (
    read_workbook, run_rules, issues_to_frames, compute_coverage, compute_coverage_matrix,
    compute_risk_score, apply_mappings, diff_runs
)

st.set_page_config(page_title="Maptrix", layout="wide")

ENGINE = get_engine()

# ---------- Bootstrap schema (for SQLite dev; for Postgres you can run schema.sql once) ----------
def bootstrap_sqlite():
    exec_sql(ENGINE, """
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    """)
    exec_sql(ENGINE, """
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
    """)
    exec_sql(ENGINE, """
    CREATE TABLE IF NOT EXISTS run_tables (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id INTEGER NOT NULL,
      table_name TEXT NOT NULL,
      data_json TEXT NOT NULL
    );
    """)
    exec_sql(ENGINE, """
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
    """)
    exec_sql(ENGINE, """
    CREATE TABLE IF NOT EXISTS issue_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      issue_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      comment TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    """)
    exec_sql(ENGINE, """
    CREATE TABLE IF NOT EXISTS cons_unit_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      from_cons_unit TEXT NOT NULL,
      to_cons_unit TEXT NOT NULL,
      note TEXT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(user_id, from_cons_unit)
    );
    """)

bootstrap_sqlite()

# ---------- Auth (FIXED) ----------
def get_user_by_email(email: str):
    return fetch_one(ENGINE, "SELECT * FROM users WHERE email=:e", {"e": email})

def _pw_for_bcrypt(password: str) -> str:
    """
    bcrypt has a 72-byte input limit. To avoid errors + unicode issues,
    we pre-hash with sha256 (always 64 hex chars), then bcrypt that.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def create_user(email: str, password: str):
    ph = bcrypt.hash(_pw_for_bcrypt(password))
    exec_sql(
        ENGINE,
        "INSERT INTO users(email,password_hash,created_at) VALUES(:e,:p,:t)",
        {"e": email, "p": ph, "t": datetime.utcnow().isoformat()},
    )

def verify_user(email: str, password: str):
    u = get_user_by_email(email)
    if not u:
        return None
    if bcrypt.verify(_pw_for_bcrypt(password), u["password_hash"]):
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
            u = verify_user(email.strip().lower(), pw)
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
                create_user(email.strip().lower(), pw)
                st.success("Account created. Please login.")
            except Exception as e:
                st.error(f"Could not create account: {e}")

    st.stop()

user = require_login()
user_id = user["id"]

# ---------- Mapping memory ----------
def load_mappings(user_id: int) -> dict:
    rows = fetch_all(
        ENGINE,
        "SELECT from_cons_unit, to_cons_unit FROM cons_unit_mappings WHERE user_id=:u",
        {"u": user_id},
    )
    return {r["from_cons_unit"]: r["to_cons_unit"] for r in rows}

def upsert_mapping(user_id: int, from_cu: str, to_cu: str, note: str = ""):
    exec_sql(
        ENGINE,
        "DELETE FROM cons_unit_mappings WHERE user_id=:u AND from_cons_unit=:f",
        {"u": user_id, "f": from_cu},
    )
    exec_sql(
        ENGINE,
        """
      INSERT INTO cons_unit_mappings(user_id, from_cons_unit, to_cons_unit, note, created_at)
      VALUES(:u,:f,:t,:n,:c)
    """,
        {"u": user_id, "f": from_cu, "t": to_cu, "n": note, "c": datetime.utcnow().isoformat()},
    )

# ---------- Runs persistence ----------
def df_to_json(df: pd.DataFrame) -> str:
    return df.to_json(orient="records")

def json_to_df(s: str) -> pd.DataFrame:
    return pd.DataFrame(json.loads(s)) if s else pd.DataFrame()

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
    run_id = run_row["id"]

    for name, df in tables.items():
        exec_sql(
            ENGINE,
            "INSERT INTO run_tables(run_id, table_name, data_json) VALUES(:r,:n,:j)",
            {"r": run_id, "n": name, "j": df_to_json(df)},
        )

    # store issues with workflow fields
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
    row = fetch_one(
        ENGINE,
        "SELECT data_json FROM run_tables WHERE run_id=:r AND table_name=:n",
        {"r": run_id, "n": table_name},
    )
    if not row:
        return pd.DataFrame()
    return json_to_df(row["data_json"])

def load_run_issues(run_id: int) -> pd.DataFrame:
    rows = fetch_all(ENGINE, "SELECT * FROM run_issues WHERE run_id=:r ORDER BY id DESC", {"r": run_id})
    return pd.DataFrame(rows)

def update_issue_status(issue_id: int, status: str, owner: str = ""):
    exec_sql(ENGINE, "UPDATE run_issues SET status=:s, owner=:o WHERE id=:i", {"s": status, "o": owner or None, "i": issue_id})

def add_comment(issue_id: int, user_id: int, comment: str):
    exec_sql(
        ENGINE,
        "INSERT INTO issue_comments(issue_id,user_id,comment,created_at) VALUES(:i,:u,:c,:t)",
        {"i": issue_id, "u": user_id, "c": comment, "t": datetime.utcnow().isoformat()},
    )

def load_comments(issue_id: int):
    return fetch_all(ENGINE, "SELECT * FROM issue_comments WHERE issue_id=:i ORDER BY id DESC", {"i": issue_id})

# ---------- UI ----------
st.sidebar.header("Maptrix")
st.sidebar.caption("build: 2026-02-15 sha256-prehash")  # helps confirm cloud redeploy
st.sidebar.caption(f"Logged in as {user['email']}")

if st.sidebar.button("Logout"):
    st.session_state.user = None
    st.rerun()

page = st.sidebar.radio("Navigate", ["Upload & Analyze", "Run History", "Mappings", "Issues Workflow"])

mappings = load_mappings(user_id)

if page == "Upload & Analyze":
    st.title("Upload & Analyze")

    reporting_date = st.date_input("Reporting date (optional)", value=None)
    uploaded = st.file_uploader("Upload Excel (.xlsx)", type=["xlsx"])

    if not uploaded:
        st.info("Upload a workbook to run Maptrix.")
        st.stop()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = tmp.name

    try:
        cu, leases, emp, sites = read_workbook(tmp_path)

        # Apply mapping memory BEFORE checks
        leases = apply_mappings(leases, mappings)
        emp = apply_mappings(emp, mappings)
        sites = apply_mappings(sites, mappings)

        cov = {
            "leases": compute_coverage(cu, leases),
            "employees": compute_coverage(cu, emp),
            "sites": compute_coverage(cu, sites),
        }

        st.sidebar.subheader("Coverage")
        for k, v in cov.items():
            total = max(int(v["master_total"]), 1)
            st.sidebar.write(f"{k}: {v['matched']}/{v['master_total']} matched ({v['unknown']} unknown)")
            st.sidebar.progress(float(v["matched"]) / total)

        issues = run_rules(cu, leases, emp, sites)
        issues_df, summary_df = issues_to_frames(issues)
        risk = compute_risk_score(issues_df, cov)
        master_units = len(set(cu["cons_unit"].astype(str)))

        col1, col2, col3 = st.columns(3)
        col1.metric("Issues", len(issues_df))
        col2.metric("Risk score (0-100)", f"{risk:.1f}")
        col3.metric("Master cons_units", master_units)

        st.subheader("Coverage Matrix")
        cov_matrix = compute_coverage_matrix(cu, leases, emp, sites)
        st.dataframe(cov_matrix, use_container_width=True)

        st.subheader("Summary")
        st.dataframe(summary_df, use_container_width=True)

        st.subheader("Issues")
        st.dataframe(issues_df, use_container_width=True)

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


elif page == "Run History":
    st.title("Run History")
    runs = list_runs(user_id)
    if not runs:
        st.info("No saved runs yet.")
        st.stop()

    run_options = {
        f"Run #{r['id']} — {str(r.get('created_at',''))[:19]} — risk {float(r.get('risk_score',0)):.1f}": r["id"]
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
        prev_run_id = runs[1]["id"] if runs[0]["id"] == run_id else runs[0]["id"]
        prev_matrix = load_run_table(prev_run_id, "coverage_matrix")
        curr_matrix = load_run_table(run_id, "coverage_matrix")
        changes = diff_runs(prev_matrix, curr_matrix)
        st.dataframe(changes, use_container_width=True)
    else:
        st.info("Need at least 2 runs to compare.")


elif page == "Mappings":
    st.title("Mappings (memory)")
    st.caption("Save how unknown cons_unit codes should map to canonical codes. Applied automatically on new uploads.")

    rows = fetch_all(ENGINE, "SELECT * FROM cons_unit_mappings WHERE user_id=:u ORDER BY id DESC", {"u": user_id})
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    st.subheader("Add / update mapping")
    from_cu = st.text_input("From cons_unit (unknown)", "")
    to_cu = st.text_input("To cons_unit (canonical)", "")
    note = st.text_input("Note (optional)", "")
    if st.button("Save mapping"):
        if not from_cu.strip() or not to_cu.strip():
            st.error("Both From and To are required.")
        else:
            upsert_mapping(user_id, from_cu.strip(), to_cu.strip(), note.strip())
            st.success("Saved mapping.")
            st.rerun()


elif page == "Issues Workflow":
    st.title("Issues Workflow")

    runs = list_runs(user_id)
    if not runs:
        st.info("No runs saved yet.")
        st.stop()

    run_id = st.selectbox("Select run", [r["id"] for r in runs])
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