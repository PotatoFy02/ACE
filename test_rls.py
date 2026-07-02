"""
Proves Row-Level Security: User B cannot read/modify User A's data.
Get tokens: run app, sign in as two Google accounts, copy each
access_token from DevTools > Application > Local Storage > supabase key.
Run: python test_rls.py  -> expect all PASS lines.
"""
import os
import jwt as pyjwt
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()
URL = os.getenv("SUPABASE_URL")
ANON = os.getenv("SUPABASE_ANON_KEY")

JWT_A = "PASTE_USER_A_ACCESS_TOKEN"
JWT_B = "PASTE_USER_B_ACCESS_TOKEN"


def client(tok):
    c = create_client(URL, ANON)
    c.postgrest.auth(tok)
    return c


def uid(tok):
    return pyjwt.decode(tok, options={"verify_signature": False})["sub"]


def run():
    a, b = client(JWT_A), client(JWT_B)
    created = a.table("projects").insert({
        "user_id": uid(JWT_A), "name": "RLS Test",
        "architecture_description": "isolation test system with a db and api",
    }).execute()
    pid = created.data[0]["id"]
    print("Setup: A created project", pid)

    stolen = b.table("projects").select("*").eq("id", pid).execute()
    print("PASS: B cannot read A's project" if not stolen.data
          else "FAIL: B READ A's project - RLS BROKEN")

    b.table("projects").delete().eq("id", pid).execute()
    still = a.table("projects").select("id").eq("id", pid).execute()
    print("PASS: B cannot delete A's project" if still.data
          else "FAIL: B DELETED A's project - RLS BROKEN")

    b_threats = b.table("threats").select("*").eq("project_id", pid).execute()
    print("PASS: B cannot read A's threats" if not b_threats.data
          else "FAIL: B READ A's threats - RLS BROKEN")

    a.table("projects").delete().eq("id", pid).execute()
    print("Cleanup done.")


if __name__ == "__main__":
    run()