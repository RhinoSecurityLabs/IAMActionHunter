#!/usr/bin/env python3
"""Debug helper for privilege escalation detection"""
import sys
import json
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: python3 debug_privesc.py <account-id> <principal-name>")
    print("Example: python3 debug_privesc.py 123456789012 MyRole")
    sys.exit(1)

account_id = sys.argv[1]
principal_name = sys.argv[2]

data_dir = Path.home() / ".iamactionhunter"
account_dir = data_dir / account_id
raw_dir = account_dir / "raw"

# Try to find principal in roles or users
principal_file = None
principal_type = None

for ptype in ["roles", "users"]:
    candidate = account_dir / ptype / f"{principal_name}.json"
    if candidate.exists():
        principal_file = candidate
        principal_type = ptype[:-1]  # Remove 's'
        break

if not principal_file:
    print(f"Principal '{principal_name}' not found in account {account_id}")
    sys.exit(1)

print(f"=== Debugging {principal_type}:{principal_name} ===\n")

# Load principal permissions
with open(principal_file, "r") as f:
    perms = json.load(f)

# Check for Glue privesc actions
required_actions = [
    "iam:passrole",
    "glue:createdevendpoint",
    "glue:getdevendpoint"
]

print("Required actions for PassExistingRoleToNewGlueDevEndpoint:")
for action in required_actions:
    if action in perms:
        resources = perms[action].get("Allow_resources", [])
        print(f"  ✓ {action}: {len(resources)} resources")
        if len(resources) <= 3:
            for r in resources:
                print(f"      {r}")
        else:
            for r in resources[:3]:
                print(f"      {r}")
            print(f"      ... and {len(resources) - 3} more")
    else:
        print(f"  ✗ {action}: NOT FOUND")

# Check for roles that trust glue
print("\n" + "="*60)
print("Checking roles that trust glue.amazonaws.com:")

trust_dir = raw_dir / "policies" / "trust"
if not trust_dir.exists():
    print("  No trust policies found")
else:
    glue_roles = []
    for trust_file in trust_dir.iterdir():
        if trust_file.suffix == ".json":
            role_name = trust_file.stem
            with open(trust_file, "r") as f:
                trust_policy = json.load(f)

            statements = trust_policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal", {})
                if isinstance(principal, dict) and "Service" in principal:
                    services = principal["Service"]
                    if isinstance(services, str):
                        services = [services]
                    if "glue.amazonaws.com" in services:
                        glue_roles.append(role_name)
                        break

    if glue_roles:
        print(f"  Found {len(glue_roles)} roles that trust glue.amazonaws.com:")
        for role in glue_roles[:10]:
            role_arn = f"arn:aws:iam::{account_id}:role/{role}"
            print(f"    {role}")

            # Check if principal can pass this role
            if "iam:passrole" in perms:
                passrole_resources = perms["iam:passrole"].get("Allow_resources", [])
                can_pass = False
                if "*" in passrole_resources:
                    can_pass = True
                else:
                    for res in passrole_resources:
                        if res.endswith("*") and role_arn.startswith(res[:-1]):
                            can_pass = True
                            break
                        if res == role_arn:
                            can_pass = True
                            break
                if can_pass:
                    print(f"      ✓ Can pass this role")
                else:
                    print(f"      ✗ Cannot pass this role (iam:PassRole resources don't match)")
        if len(glue_roles) > 10:
            print(f"    ... and {len(glue_roles) - 10} more")
    else:
        print("  ✗ No roles found that trust glue.amazonaws.com")
        print("  This is why the privesc is not detected!")

print("\n" + "="*60)
print("Summary:")
has_all_actions = all(action in perms for action in required_actions)
if has_all_actions:
    print("  ✓ Has all required actions")
else:
    print("  ✗ Missing some required actions")

if glue_roles:
    passable_glue_roles = []
    if "iam:passrole" in perms:
        passrole_resources = perms["iam:passrole"].get("Allow_resources", [])
        for role in glue_roles:
            role_arn = f"arn:aws:iam::{account_id}:role/{role}"
            can_pass = False
            if "*" in passrole_resources:
                can_pass = True
            else:
                for res in passrole_resources:
                    if res.endswith("*") and role_arn.startswith(res[:-1]):
                        can_pass = True
                        break
                    if res == role_arn:
                        can_pass = True
                        break
            if can_pass:
                passable_glue_roles.append(role)

    if passable_glue_roles:
        print(f"  ✓ Can pass {len(passable_glue_roles)} roles that trust glue.amazonaws.com")
        print(f"\n  → Privesc SHOULD be detected for these roles:")
        for role in passable_glue_roles[:5]:
            print(f"      {role}")
    else:
        print("  ✗ Cannot pass any roles that trust glue.amazonaws.com")
        print("  → Privesc will NOT be detected (no valid targets)")
else:
    print("  ✗ No roles trust glue.amazonaws.com")
    print("  → Privesc will NOT be detected (no valid targets)")
