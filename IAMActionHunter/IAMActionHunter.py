import json
import os
import argparse
import sys
import traceback

from policyuniverse.statement import Statement

from IAMActionHunter.lib.data_collection import get_all_iam_policies
from IAMActionHunter.lib.create_csv import process_json_and_append_to_csv
from IAMActionHunter.lib.text_formatter import color

import IAMActionHunter.configs.all as configs

from pathlib import Path
data_dir = Path.home() / ".iamactionhunter"
data_dir.mkdir(exist_ok=True)


def ensure_list(item):
    if isinstance(item, list):
        return item
    else:
        return [item]


def get_file_list(directory):
    if not os.path.exists(directory):
        return []
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    return files


def filter_files(files, filter):
    filtered_files = []
    for file in files:
        if filter.lower() in file.lower():
            filtered_files.append(file)
    return filtered_files


def parse_multi_value_arg(arg_value):
    """Parse an argument that can be a single value, comma-separated, or file path."""
    if arg_value is None:
        return None
    arg_path = Path(arg_value)
    if arg_path.is_file():
        return [line.strip() for line in arg_path.read_text().splitlines() if line.strip()]
    else:
        return [v.strip() for v in arg_value.split(",") if v.strip()]


# =============================================================================
# List Command
# =============================================================================

def cmd_list(args):
    """List available accounts."""
    print("Available accounts:")
    print()
    for account in os.listdir(data_dir):
        account_path = data_dir / account
        if account_path.is_dir():
            has_raw = (account_path / "raw").exists()
            has_permissions = (account_path / "roles").exists() or (account_path / "users").exists()
            status = []
            if has_raw:
                status.append("collected")
            if has_permissions:
                status.append("analyzed")
            status_str = ", ".join(status) if status else "empty"
            print(f"  {account} ({status_str})")


# =============================================================================
# Collect Command
# =============================================================================

def cmd_collect(args):
    """Collect and analyze IAM policies."""
    success = get_all_iam_policies(target_aws_profile=args.profile, account_id=args.account)
    sys.exit(0 if success else 1)


# =============================================================================
# Query Command
# =============================================================================

def process_cli_query(permissions_json, principal_type_name, args, filter_permissions=None):
    try:
        query_results = {}
        query = args.query.split(",")
        query = Statement({"Action": query}).actions_expanded

        for action in query:
            if permissions_json.get(action):
                query_results.update({action: permissions_json.get(action)})

        if filter_permissions:
            query_results = {action: data for action, data in query_results.items()
                            if action not in filter_permissions}

        if args.all_or_none:
            if not all(item in query_results for item in query):
                query_results = {}

        if args.csv:
            process_json_and_append_to_csv(query_results, args.csv, principal_type_name)

        for action in query_results:
            action_object = query_results[action]
            if action_object["Allow_resources"]:
                print(
                    f"{color.green('[+]')} {color.green(principal_type_name)} can perform {color.green(action)} on the"
                    " following resources:"
                )
                for resource in action_object["Allow_resources"]:
                    print(resource)
                if action_object["Allow_conditions"]:
                    print(color.yellow("[-] With the following conditions:"))
                    for condition in action_object["Allow_conditions"]:
                        print(condition)
                if action_object["Deny_resources"]:
                    print(color.red("[-] If the resources are not included in:"))
                    for resource in action_object["Deny_resources"]:
                        print(resource)
                    if action_object["Deny_conditions"]:
                        print("[-] These Deny rules only apply if the following conditions are met:")
                        for condition in action_object["Deny_conditions"]:
                            print(condition)
                print()

    except Exception as e:
        print()
        print(f"[!!] Error with {principal_type_name}")
        print(e)
        traceback.print_exc()
        print()


def process_config_file_query(permissions_json, config, principal_type_name, args, filter_permissions=None):
    query_results = {}
    query = config["ActionsNeeded"]
    all_or_none = config["AllOrNone"]
    query = Statement({"Action": query}).actions_expanded

    for action in query:
        if permissions_json.get(action):
            query_results.update({action: permissions_json.get(action)})

    if filter_permissions:
        query_results = {action: data for action, data in query_results.items()
                        if action not in filter_permissions}

    if all_or_none:
        if not all(item in query_results for item in query):
            query_results = {}

    if args.csv:
        process_json_and_append_to_csv(query_results, args.csv, principal_type_name)

    if query_results:
        print(f"{color.green('[+]')} {color.green(principal_type_name)} vulnerable to {color.green(config['Name'])}:")
        for action in query_results:
            action_object = query_results[action]
            if action_object["Allow_resources"]:
                print(f"{color.green(action)}")
                for resource in action_object["Allow_resources"]:
                    print(resource)
                if action_object["Allow_conditions"]:
                    print(color.yellow("[-] With the following conditions:"))
                    for condition in action_object["Allow_conditions"]:
                        print(condition)
                if action_object["Deny_resources"]:
                    print(color.red("[-] If the resources are not included in:"))
                    for resource in action_object["Deny_resources"]:
                        print(resource)
                    if action_object["Deny_conditions"]:
                        print("[-] These Deny rules only apply if the following conditions are met:")
                        for condition in action_object["Deny_conditions"]:
                            print(condition)


def cmd_query(args):
    """Query permissions for users/roles."""
    if not args.query and not args.config:
        print("Error: --query or --config is required")
        sys.exit(1)

    output_directory = data_dir / args.account
    permissions_directory = output_directory

    if not (permissions_directory / "roles").exists() and not (permissions_directory / "users").exists():
        if (output_directory / "raw").exists():
            print(f"Account {args.account} has been collected but not analyzed.")
            print(f"Run: iah collect --account {args.account}")
        else:
            print(f"Account {args.account} does not exist.")
            print("Run: iah collect --profile <aws-profile>")
        sys.exit(1)

    role_directory = permissions_directory / "roles"
    user_directory = permissions_directory / "users"

    role_files = get_file_list(role_directory)
    user_files = get_file_list(user_directory)
    all_files = user_files + role_files

    # Filter by role/user
    filtered_roles = []
    filtered_users = []
    if args.role:
        role_path = Path(args.role)
        if role_path.is_file():
            roles = [line.strip() for line in role_path.read_text().splitlines() if line.strip()]
        else:
            roles = [r.strip() for r in args.role.split(",")]
        for role in roles:
            filtered_roles += filter_files(role_files, f"{role}.json")
    if args.user:
        for user in args.user.split(","):
            filtered_users += filter_files(user_files, f"{user}.json")
    if args.role or args.user:
        all_files = filtered_roles + filtered_users

    if not all_files:
        print("[-] No users or roles found for that query")
        sys.exit(1)

    # Load config if specified
    query_config = None
    if args.config:
        builtin_configs = vars(configs)
        if args.config in builtin_configs:
            query_config = builtin_configs[args.config]
        else:
            try:
                with open(args.config, "r") as f:
                    query_config = json.loads(f.read())
            except FileNotFoundError:
                print(f"{args.config} does not exist. Builtin config options are:")
                print()
                for config in builtin_configs:
                    if not config.startswith("__"):
                        print(config)
                print()
                sys.exit(1)
            except json.decoder.JSONDecodeError:
                print(f"{args.config} is not a valid config JSON file")
                sys.exit(1)

    # Load filter principal
    filter_permissions = None
    if args.filter_principal:
        filter_file = None
        for dir_type in ['roles', 'users']:
            potential_path = permissions_directory / dir_type / f"{args.filter_principal}.json"
            if potential_path.exists():
                filter_file = potential_path
                break
        if filter_file:
            with open(filter_file, "r") as f:
                filter_permissions = json.load(f)
        else:
            print(f"[-] Filter principal '{args.filter_principal}' not found")
            sys.exit(1)

    # Process files
    for permission_file in all_files:
        principal_type = permission_file.split("/")[-2][:-1]
        principal_name = permission_file.split("/")[-1].split(".json")[0]

        with open(permission_file, "r") as f:
            permissions = json.load(f)

        if query_config:
            for config in query_config:
                process_config_file_query(permissions, config, f"{principal_type}:{principal_name}", args, filter_permissions)
        else:
            process_cli_query(permissions, f"{principal_type}:{principal_name}", args, filter_permissions)


# =============================================================================
# Privesc Command
# =============================================================================

def load_trust_policies(raw_dir):
    trust_policies = {}
    trust_dir = raw_dir / "policies" / "trust"
    if trust_dir.exists():
        for trust_file in trust_dir.iterdir():
            if trust_file.suffix == ".json":
                role_name = trust_file.stem
                with open(trust_file, "r") as f:
                    trust_policies[role_name] = json.load(f)
    return trust_policies


def analyze_trust_policy(trust_policy, account_id, source_principal_arn=None, source_principal_type=None):
    """
    Analyze if a trust policy allows a specific principal to assume the role.

    Args:
        trust_policy: The trust policy document
        account_id: The account ID where the role exists
        source_principal_arn: ARN of the principal trying to assume (e.g., arn:aws:iam::123:role/MyRole)
        source_principal_type: Type of principal ("role" or "user")

    Returns:
        Trust reason string if the principal is trusted, None otherwise
    """
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    reasons = []
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        assume_allowed = any(a in ["sts:AssumeRole", "sts:*", "*"] for a in actions)
        if not assume_allowed:
            continue

        principal = statement.get("Principal", {})
        conditions = statement.get("Condition", {})

        is_trusted = False
        reason = None

        if principal == "*":
            is_trusted = True
            reason = "Principal: * (anyone)"
        elif isinstance(principal, dict):
            if "AWS" in principal:
                aws_principals = principal["AWS"]
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if p == "*":
                        is_trusted = True
                        reason = "Principal: * (anyone)"
                        break
                    elif p == account_id or p == f"arn:aws:iam::{account_id}:root":
                        # Account root - any principal in the account can assume
                        is_trusted = True
                        reason = f"Principal: Same account ({account_id})"
                        break
                    elif source_principal_arn:
                        # Check if the specific principal is trusted
                        if p == source_principal_arn:
                            is_trusted = True
                            reason = f"Principal: {p}"
                            break
                        # Handle wildcard patterns in the trusted principal
                        if p.endswith("*") and source_principal_arn.startswith(p[:-1]):
                            is_trusted = True
                            reason = f"Principal: {p} (wildcard match)"
                            break

        if is_trusted and reason:
            if conditions:
                reason += f"; Conditions: {json.dumps(conditions)}"
            reasons.append(reason)

    return "; ".join(reasons) if reasons else None


def check_cross_account_assumable_roles(principal_perms, trust_policies, source_account, target_account, source_principal_name=None, source_principal_type=None):
    """
    Check if a principal from source_account can assume roles in target_account.

    Args:
        principal_perms: The permissions dict for the source principal
        trust_policies: Dict of role_name -> trust_policy for the target account
        source_account: The source AWS account ID
        target_account: The target AWS account ID
        source_principal_name: Name of the source principal (e.g., "MyRole")
        source_principal_type: Type of source principal ("role" or "user")

    Returns:
        List of (role_name, trust_reason) tuples for cross-account assumable roles.
    """
    assumable = []

    assume_role_perms = principal_perms.get("sts:assumerole", {})
    if not assume_role_perms:
        return assumable

    allowed_resources = assume_role_perms.get("Allow_resources", [])
    if not allowed_resources:
        return assumable

    # Build source principal ARN if we have the info
    source_principal_arn = None
    if source_principal_name and source_principal_type:
        source_principal_arn = f"arn:aws:iam::{source_account}:{source_principal_type}/{source_principal_name}"

    for role_name, trust_policy in trust_policies.items():
        role_arn = f"arn:aws:iam::{target_account}:role/{role_name}"

        # Check if principal can assume this role (resource permission)
        can_assume = False
        for resource in allowed_resources:
            if resource == "*":
                can_assume = True
                break
            if resource.endswith("*") and role_arn.startswith(resource[:-1]):
                can_assume = True
                break
            if resource == role_arn:
                can_assume = True
                break

        if not can_assume:
            continue

        # Check if role trusts the source principal
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        is_trusted = False
        trust_reason = None

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            assume_allowed = any(a in ["sts:AssumeRole", "sts:*", "*"] for a in actions)
            if not assume_allowed:
                continue

            principal = statement.get("Principal", {})

            if principal == "*":
                is_trusted = True
                trust_reason = "Principal: * (anyone)"
                break
            elif isinstance(principal, dict) and "AWS" in principal:
                aws_principals = principal["AWS"]
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if p == "*":
                        is_trusted = True
                        trust_reason = "Principal: * (anyone)"
                        break
                    elif p == source_account or p == f"arn:aws:iam::{source_account}:root":
                        # Account root - any principal in the source account can assume
                        is_trusted = True
                        trust_reason = f"Principal: Account {source_account} (root)"
                        break
                    elif source_principal_arn:
                        # Check if the specific principal is trusted
                        if p == source_principal_arn:
                            is_trusted = True
                            trust_reason = f"Principal: {p}"
                            break
                        # Handle wildcard patterns in the trusted principal
                        if p.endswith("*") and source_principal_arn.startswith(p[:-1]):
                            is_trusted = True
                            trust_reason = f"Principal: {p} (wildcard match)"
                            break

        if is_trusted and trust_reason:
            assumable.append((role_name, trust_reason))

    return assumable


def get_assumable_roles(principal_permissions, trust_policies, account_id, source_principal_name=None, source_principal_type=None):
    """
    Get roles that a principal can assume.

    Args:
        principal_permissions: The permissions dict for the source principal
        trust_policies: Dict of role_name -> trust_policy
        account_id: The AWS account ID
        source_principal_name: Name of the source principal (e.g., "MyRole")
        source_principal_type: Type of source principal ("role" or "user")

    Returns:
        List of (role_name, trust_reason) tuples
    """
    assumable = []

    assume_role_perms = principal_permissions.get("sts:assumerole", {})
    if not assume_role_perms:
        return assumable

    allowed_resources = assume_role_perms.get("Allow_resources", [])
    if not allowed_resources:
        return assumable

    # Build source principal ARN if we have the info
    source_principal_arn = None
    if source_principal_name and source_principal_type:
        source_principal_arn = f"arn:aws:iam::{account_id}:{source_principal_type}/{source_principal_name}"

    for role_name, trust_policy in trust_policies.items():
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        can_assume = False
        for resource in allowed_resources:
            if resource == "*":
                can_assume = True
                break
            if resource.endswith("*") and role_arn.startswith(resource[:-1]):
                can_assume = True
                break
            if resource == role_arn:
                can_assume = True
                break

        if can_assume:
            trust_reason = analyze_trust_policy(
                trust_policy, account_id,
                source_principal_arn=source_principal_arn,
                source_principal_type=source_principal_type
            )
            if trust_reason:
                assumable.append((role_name, trust_reason))

    return assumable


def compute_permission_gain(source_permissions, target_permissions):
    gained = {}
    
    for action, perms in target_permissions.items():
        target_resources = set(perms.get("Allow_resources", []))
        if not target_resources:
            continue
        
        source_perms = source_permissions.get(action, {})
        source_resources = set(source_perms.get("Allow_resources", []))
        
        if "*" in source_resources:
            continue
        
        if "*" in target_resources and "*" not in source_resources:
            gained[action] = {"Allow_resources": ["*"]}
        else:
            new_resources = target_resources - source_resources
            if new_resources:
                gained[action] = {"Allow_resources": list(new_resources)}
    
    return gained


def get_principals_with_action(action_query, role_permissions, user_permissions):
    """
    Find principals that have the specified action(s).
    Args:
        action_query (str): Action query like "s3:GetObject" or "iam:*"
        role_permissions (dict): Dict of role_name -> permissions
        user_permissions (dict): Dict of user_name -> permissions
    Returns:
        dict: {"users": {user_name: [matching_actions]}, "roles": {role_name: [matching_actions]}}
    """
    from policyuniverse.statement import Statement

    # Expand wildcards in the query
    query_actions = Statement({"Action": action_query.split(",")}).actions_expanded

    targets = {"users": {}, "roles": {}}

    # Check roles
    for role_name, perms in role_permissions.items():
        matching_actions = []
        for query_action in query_actions:
            query_lower = query_action.lower()
            if query_lower in perms:
                action_perms = perms[query_lower]
                if action_perms.get("Allow_resources"):
                    matching_actions.append(query_action)

        if matching_actions:
            targets["roles"][role_name] = matching_actions

    # Check users
    for user_name, perms in user_permissions.items():
        matching_actions = []
        for query_action in query_actions:
            query_lower = query_action.lower()
            if query_lower in perms:
                action_perms = perms[query_lower]
                if action_perms.get("Allow_resources"):
                    matching_actions.append(query_action)

        if matching_actions:
            targets["users"][user_name] = matching_actions

    return targets


def get_principals_with_policy(raw_dir, policy_name):
    """
    Find principals that have the specified policy attached.
    Args:
        raw_dir: Path to raw data directory
        policy_name (str): Policy name to search for (e.g., "AdministratorAccess")
    Returns:
        dict: {"users": set(user_names), "roles": set(role_names)}
    """
    targets = {"users": set(), "roles": set()}
    policy_name_lower = policy_name.lower()

    roles_dir = raw_dir / "principals" / "roles"
    if roles_dir.exists():
        for manifest_file in roles_dir.iterdir():
            if manifest_file.suffix == ".json":
                role_name = manifest_file.stem
                with open(manifest_file, "r") as f:
                    manifest = json.load(f)
                for policy_arn in manifest.get("managed", []):
                    if policy_name_lower in policy_arn.lower():
                        targets["roles"].add(role_name)
                        break

    users_dir = raw_dir / "principals" / "users"
    if users_dir.exists():
        for manifest_file in users_dir.iterdir():
            if manifest_file.suffix == ".json":
                user_name = manifest_file.stem
                with open(manifest_file, "r") as f:
                    manifest = json.load(f)
                for policy_arn in manifest.get("managed", []):
                    if policy_name_lower in policy_arn.lower():
                        targets["users"].add(user_name)
                        break

    return targets


def extract_cross_account_role_arns(principal_perms, target_account):
    """
    Extract role ARNs from a principal's permissions that belong to the target account.
    Returns list of (role_name, role_arn) tuples.
    """
    assume_role_perms = principal_perms.get("sts:assumerole", {})
    if not assume_role_perms:
        return []

    allowed_resources = assume_role_perms.get("Allow_resources", [])
    if not allowed_resources:
        return []

    cross_account_roles = []
    target_prefix = f"arn:aws:iam::{target_account}:role/"

    for resource in allowed_resources:
        if resource == "*":
            # Wildcard - could assume any role in any account
            cross_account_roles.append(("*", f"*@{target_account}"))
        elif resource.startswith(target_prefix):
            # Specific role in target account
            role_name = resource.split("/")[-1]
            if role_name.endswith("*"):
                # Wildcard role pattern
                cross_account_roles.append((role_name, resource))
            else:
                cross_account_roles.append((role_name, resource))
        elif resource.endswith("*"):
            # Check if wildcard pattern matches target account
            if resource.startswith(f"arn:aws:iam::{target_account}:"):
                cross_account_roles.append((resource.split("/")[-1], resource))

    return cross_account_roles


def check_other_privesc_methods(principal_perms, trust_policies, account_id, all_roles, all_users):
    """Check for non-AssumeRole privilege escalation methods."""
    # Import here to avoid circular dependency
    from IAMActionHunter.lib.graph import check_privesc_methods

    principal_perms_lower = {k.lower(): v for k, v in principal_perms.items()}
    return check_privesc_methods(principal_perms_lower, trust_policies, account_id, all_roles, all_users)


def cmd_privesc(args):
    """Analyze privilege escalation paths."""
    # Parse cross-account argument
    cross_accounts = []
    if hasattr(args, 'cross_account') and args.cross_account:
        cross_accounts = [acc.strip() for acc in args.cross_account.split(",") if acc.strip()]

    all_accounts = [args.account] + cross_accounts

    # Load data for all accounts
    accounts_data = {}
    for account_id in all_accounts:
        account_dir = data_dir / account_id
        raw_dir = account_dir / "raw"
        permissions_dir = account_dir

        # For the primary account in cross-account mode, we only need permissions, not trust policies
        is_primary = (account_id == args.account)
        is_cross_account_mode = bool(cross_accounts)

        if not raw_dir.exists():
            if is_primary:
                print(f"Error: No raw data found for primary account {account_id}.")
                return
            print(f"Warning: No raw data found for account {account_id}. Skipping.")
            continue

        trust_policies = load_trust_policies(raw_dir)

        # Trust policies are required for target accounts, but optional for primary in cross-account mode
        if not trust_policies:
            if is_primary and not is_cross_account_mode:
                # Same-account analysis needs trust policies
                print(f"Error: No trust policies found for primary account {account_id}.")
                return
            elif not is_primary:
                # Target account without trust policies - skip but allow potential privesc detection
                print(f"Warning: No trust policies found for account {account_id}.")
                # Continue loading to allow potential cross-account role detection

        # Load role permissions
        role_permissions = {}
        roles_dir = permissions_dir / "roles"
        if roles_dir.exists():
            for perm_file in roles_dir.iterdir():
                if perm_file.suffix == ".json":
                    role_name = perm_file.stem
                    with open(perm_file, "r") as f:
                        role_permissions[role_name] = json.load(f)

        # Load user permissions
        user_permissions = {}
        users_dir = permissions_dir / "users"
        if users_dir.exists():
            for perm_file in users_dir.iterdir():
                if perm_file.suffix == ".json":
                    user_name = perm_file.stem
                    with open(perm_file, "r") as f:
                        user_permissions[user_name] = json.load(f)

        accounts_data[account_id] = {
            "raw_dir": raw_dir,
            "trust_policies": trust_policies if trust_policies else {},
            "role_permissions": role_permissions,
            "user_permissions": user_permissions,
            "roles_dir": roles_dir,
            "users_dir": users_dir
        }

    if not accounts_data:
        print("No valid account data found.")
        return

    if args.account not in accounts_data:
        print(f"Error: Primary account {args.account} could not be loaded.")
        return

    # Use primary account data for backward compatibility
    primary_data = accounts_data[args.account]
    raw_dir = primary_data["raw_dir"]
    trust_policies = primary_data["trust_policies"]
    role_permissions = primary_data["role_permissions"]
    user_permissions = primary_data["user_permissions"]
    roles_dir = primary_data["roles_dir"]
    users_dir = primary_data["users_dir"]

    all_roles = set(role_permissions.keys())
    all_users = set(user_permissions.keys())

    # Handle --target-policy and --target-action flags
    target_principals = None
    target_policy = getattr(args, 'target_policy', None)
    target_action = getattr(args, 'target_action', None)

    if target_policy and target_action:
        print("Error: Cannot specify both --target-policy and --target-action")
        return

    if target_policy:
        policy_targets = get_principals_with_policy(raw_dir, target_policy)
        # Convert sets to dicts for consistency with target_action format
        target_principals = {
            "roles": {r: [] for r in policy_targets["roles"]},
            "users": {u: [] for u in policy_targets["users"]}
        }
        total_targets = len(target_principals["users"]) + len(target_principals["roles"])
        if total_targets == 0:
            print(f"Warning: No principals found with policy matching '{target_policy}'")
        else:
            print(f"Found {total_targets} target principals with '{target_policy}':")
            if target_principals["roles"]:
                print(f"  Roles: {', '.join(sorted(list(target_principals['roles'].keys())[:10]))}")
                if len(target_principals["roles"]) > 10:
                    print(f"    ... and {len(target_principals['roles']) - 10} more")
            if target_principals["users"]:
                print(f"  Users: {', '.join(sorted(list(target_principals['users'].keys())[:10]))}")
                if len(target_principals["users"]) > 10:
                    print(f"    ... and {len(target_principals['users']) - 10} more")
            print()

    elif target_action:
        target_principals = get_principals_with_action(target_action, role_permissions, user_permissions)
        total_targets = len(target_principals["users"]) + len(target_principals["roles"])
        if total_targets == 0:
            print(f"Warning: No principals found with action matching '{target_action}'")
        else:
            print(f"Found {total_targets} target principals with '{target_action}':")
            if target_principals["roles"]:
                print(f"  Roles: {', '.join(sorted(list(target_principals['roles'].keys())[:10]))}")
                if len(target_principals["roles"]) > 10:
                    print(f"    ... and {len(target_principals['roles']) - 10} more")
            if target_principals["users"]:
                print(f"  Users: {', '.join(sorted(list(target_principals['users'].keys())[:10]))}")
                if len(target_principals["users"]) > 10:
                    print(f"    ... and {len(target_principals['users']) - 10} more")
            print()

    # Collect principals to check
    principals_to_check = []

    if users_dir.exists():
        for perm_file in users_dir.iterdir():
            if perm_file.suffix == ".json":
                principals_to_check.append(("user", perm_file.stem, perm_file))

    if roles_dir.exists():
        for perm_file in roles_dir.iterdir():
            if perm_file.suffix == ".json":
                principals_to_check.append(("role", perm_file.stem, perm_file))

    # Filter principals
    if args.role or args.user:
        filter_names = set()
        if args.role:
            role_path = Path(args.role)
            if role_path.is_file():
                filter_names.update(line.strip().lower() for line in role_path.read_text().splitlines() if line.strip())
            else:
                filter_names.update(r.strip().lower() for r in args.role.split(","))
        if args.user:
            user_path = Path(args.user)
            if user_path.is_file():
                filter_names.update(line.strip().lower() for line in user_path.read_text().splitlines() if line.strip())
            else:
                filter_names.update(u.strip().lower() for u in args.user.split(","))

        principals_to_check = [(t, n, f) for t, n, f in principals_to_check if n.lower() in filter_names]

    # Filter by --start
    if hasattr(args, 'start') and args.start:
        start_principals = parse_multi_value_arg(args.start)
        if start_principals:
            start_set = set(s.lower() for s in start_principals)
            principals_to_check = [(t, n, f) for t, n, f in principals_to_check if n.lower() in start_set]

    if not principals_to_check:
        print("No principals found to analyze.")
        return

    # If cross-account is specified, skip same-account analysis
    if not cross_accounts:
        print(f"Analyzing privilege escalation paths for {len(principals_to_check)} principals...\n")
    else:
        print(f"Analyzing cross-account privilege escalation paths across {len(all_accounts)} accounts...\n")

    found_privesc = False

    # Only do same-account analysis if --cross-account is NOT specified
    if not cross_accounts:
        for ptype, pname, pfile in principals_to_check:
            with open(pfile, "r") as f:
                principal_perms = json.load(f)

            principal_perms_lower = {k.lower(): v for k, v in principal_perms.items()}

            # Check AssumeRole privilege escalation
            assumable_roles = get_assumable_roles(principal_perms_lower, trust_policies, args.account, pname, ptype)

            for role_name, trust_reason in assumable_roles:
                if ptype == "role" and pname == role_name:
                    continue

                # If target_action is specified, only show paths to target principals
                if target_principals and role_name not in target_principals["roles"]:
                    continue

                target_perms = role_permissions.get(role_name, {})
                if not target_perms:
                    continue

                gained = compute_permission_gain(principal_perms, target_perms)

                if gained:
                    found_privesc = True
                    target_suffix = ""
                    if target_principals and role_name in target_principals["roles"]:
                        target_actions = target_principals["roles"][role_name]
                        target_suffix = f" {color.yellow('→ TARGET')} (has: {', '.join(target_actions[:3])}{'...' if len(target_actions) > 3 else ''})"

                    print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can assume {color.green(f'role:{role_name}')} (AssumeRole){target_suffix}")
                    print(f"    Trust: {trust_reason}")

                    if target_policy:
                        # Simplified output when --target-policy is specified
                        print(f"    {color.yellow('Gains:')} {len(gained)} permissions")
                    else:
                        print(f"    {color.yellow('Gains:')}")
                        services = {}
                        for action in gained:
                            svc = action.split(":")[0] if ":" in action else action
                            if svc not in services:
                                services[svc] = []
                            services[svc].append(action)

                        for svc in sorted(services.keys()):
                            actions = services[svc]
                            if len(actions) > 5:
                                print(f"      {svc}: {len(actions)} actions ({', '.join(sorted(actions)[:3])}...)")
                            else:
                                print(f"      {svc}: {', '.join(sorted(actions))}")
                    print()

            # Check other privilege escalation methods
            other_privescs = check_other_privesc_methods(principal_perms, trust_policies, args.account, all_roles, all_users)

            for privesc_name, target_type, targets in other_privescs:
                if ptype == "role" and target_type == "role":
                    # Filter out self-targeting for roles
                    targets = [(t, c) for t, c in targets if t != pname and t != "ANY_ROLE"]
                elif ptype == "user" and target_type == "user":
                    # Filter out self-targeting for users
                    targets = [(t, c) for t, c in targets if t != pname and t != "ANY_USER"]

                # Filter by target_action if specified
                if target_principals:
                    if target_type == "role":
                        targets = [(t, c) for t, c in targets if t in target_principals["roles"] or t == "ANY_ROLE"]
                    elif target_type == "user":
                        targets = [(t, c) for t, c in targets if t in target_principals["users"] or t == "ANY_USER"]
                    # For resource type, we can't filter easily, so skip if target_action is set
                    elif target_type == "resource":
                        continue

                if not targets:
                    continue

                found_privesc = True

                if target_type == "role":
                    target_list = [t for t, _ in targets]
                    has_conditions = any(c for _, c in targets)
                    cond_str = " (conditional)" if has_conditions else ""

                    # Mark which targets have the target action
                    marked_targets = []
                    for t in target_list:
                        if target_principals and t in target_principals["roles"]:
                            target_actions = target_principals["roles"][t]
                            marked_targets.append(f"{t} {color.yellow('→ TARGET')}")
                        else:
                            marked_targets.append(t)

                    if len(target_list) > 5:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on {len(target_list)} roles:")
                        print(f"    {', '.join(sorted(marked_targets)[:5])}...")
                    else:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on roles:")
                        print(f"    {', '.join(sorted(marked_targets))}")
                elif target_type == "user":
                    target_list = [t for t, _ in targets]
                    has_conditions = any(c for _, c in targets)
                    cond_str = " (conditional)" if has_conditions else ""

                    # Mark which targets have the target action
                    marked_targets = []
                    for t in target_list:
                        if target_principals and t in target_principals["users"]:
                            target_actions = target_principals["users"][t]
                            marked_targets.append(f"{t} {color.yellow('→ TARGET')}")
                        else:
                            marked_targets.append(t)

                    if len(target_list) > 5:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on {len(target_list)} users:")
                        print(f"    {', '.join(sorted(marked_targets)[:5])}...")
                    else:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on users:")
                        print(f"    {', '.join(sorted(marked_targets))}")
                elif target_type == "resource":
                    resources = [t for t, _ in targets]
                    has_conditions = any(c for _, c in targets)
                    cond_str = " (conditional)" if has_conditions else ""
                    if "*" in resources:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on any resource (*)")
                    elif len(resources) > 3:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on {len(resources)} resources:")
                        print(f"    {resources[0]}")
                        print(f"    {resources[1]}")
                        print(f"    ... and {len(resources) - 2} more")
                    else:
                        print(f"{color.green('[+]')} {color.green(f'{ptype}:{pname}')} can use {color.green(privesc_name)}{cond_str} on resources:")
                        for res in resources:
                            print(f"    {res}")
                print()

    # Check for cross-account privilege escalation (only if --cross-account is specified)
    if cross_accounts:
        # Only check the filtered principals from the primary account
        source_account = args.account

        for ptype, principal_name, pfile in principals_to_check:
            with open(pfile, "r") as f:
                principal_perms = json.load(f)

            principal_perms_lower = {k.lower(): v for k, v in principal_perms.items()}

            # Check against target accounts (cross_accounts only, not the primary account)
            for target_account in cross_accounts:
                target_data = accounts_data.get(target_account)

                if not target_data:
                    # No raw data for target account - show potential privesc based on permissions only
                    potential_roles = extract_cross_account_role_arns(principal_perms_lower, target_account)
                    if potential_roles:
                        found_privesc = True
                        print(f"{color.yellow('[?]')} {color.yellow(f'{ptype}:{principal_name}@{source_account}')} has permissions to assume roles in {color.yellow(f'{target_account}')} (Potential Cross-Account AssumeRole)")
                        print(f"    {color.yellow('Note:')} Trust policies not available - cannot verify if roles trust source account")
                        print(f"    {color.yellow('Potential roles:')}")
                        for role_name, role_arn in potential_roles[:10]:
                            print(f"      {role_arn}")
                        if len(potential_roles) > 10:
                            print(f"      ... and {len(potential_roles) - 10} more")
                        print()
                    continue

                target_trust_policies = target_data["trust_policies"]
                target_role_perms = target_data["role_permissions"]

                # Check cross-account AssumeRole
                cross_assumable = check_cross_account_assumable_roles(
                    principal_perms_lower,
                    target_trust_policies,
                    source_account,
                    target_account,
                    principal_name,
                    ptype
                )

                for role_name, trust_reason in cross_assumable:
                    # Filter by target_action if specified
                    if target_principals:
                        # Need to check if this role has the target action
                        target_role_perms_data = target_role_perms.get(role_name, {})
                        has_target_action = False
                        if target_principals["roles"]:
                            # Check if any target principal from any account matches
                            for acc_data in accounts_data.values():
                                if role_name in acc_data["role_permissions"]:
                                    role_data = acc_data["role_permissions"][role_name]
                                    for action in target_principals["roles"].get(role_name, []):
                                        if action.lower() in {k.lower() for k in role_data.keys()}:
                                            has_target_action = True
                                            break
                        if not has_target_action:
                            continue

                    target_perms = target_role_perms.get(role_name, {})
                    if not target_perms:
                        continue

                    gained = compute_permission_gain(principal_perms, target_perms)

                    if gained:
                        found_privesc = True
                        target_suffix = ""
                        if target_principals and role_name in target_role_perms:
                            # Check if this role has target actions
                            target_actions = []
                            for action in target_principals.get("roles", {}).get(role_name, []):
                                if action.lower() in {k.lower() for k in target_perms.keys()}:
                                    target_actions.append(action)
                            if target_actions:
                                target_suffix = f" {color.yellow('→ TARGET')} (has: {', '.join(target_actions[:3])}{'...' if len(target_actions) > 3 else ''})"

                        print(f"{color.green('[+]')} {color.yellow(f'{ptype}:{principal_name}@{source_account}')} can assume {color.yellow(f'role:{role_name}@{target_account}')} (Cross-Account AssumeRole){target_suffix}")
                        print(f"    Trust: {trust_reason}")

                        if target_policy:
                            # Simplified output when --target-policy is specified
                            print(f"    {color.yellow('Gains:')} {len(gained)} permissions")
                        else:
                            print(f"    {color.yellow('Gains:')}")
                            services = {}
                            for action in gained:
                                svc = action.split(":")[0] if ":" in action else action
                                if svc not in services:
                                    services[svc] = []
                                services[svc].append(action)

                            for svc in sorted(services.keys()):
                                actions = services[svc]
                                if len(actions) > 5:
                                    print(f"      {svc}: {len(actions)} actions ({', '.join(sorted(actions)[:3])}...)")
                                else:
                                    print(f"      {svc}: {', '.join(sorted(actions))}")
                        print()

    if not found_privesc:
        print("No privilege escalation paths found.")


# =============================================================================
# Graph Command
# =============================================================================

def cmd_graph(args):
    """Generate Neo4j graph."""
    # Import here to avoid requiring neo4j if not using graph command
    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("Neo4j driver not installed. Run: pip install neo4j")
        sys.exit(1)
    
    from IAMActionHunter.lib.graph import generate_graph
    generate_graph(args, data_dir)


# =============================================================================
# Main / Argument Parsing
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="iah",
        description="IAMActionHunter - AWS IAM policy analysis and privilege escalation detection"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- list ---
    parser_list = subparsers.add_parser("list", help="List available accounts")
    parser_list.set_defaults(func=cmd_list)

    # --- collect ---
    parser_collect = subparsers.add_parser("collect", help="Collect and analyze IAM policies from AWS")
    parser_collect.add_argument("--profile", help="AWS profile to use for authentication")
    parser_collect.add_argument("--account", help="Account ID to re-analyze existing data (skips API calls)")
    parser_collect.set_defaults(func=cmd_collect)

    # --- query ---
    parser_query = subparsers.add_parser("query", help="Query permissions for users/roles")
    parser_query.add_argument("--account", required=True, help="Account ID to query")
    parser_query.add_argument("--query", help="Permissions to query (e.g., s3:GetObject or s3:*)")
    parser_query.add_argument("--config", help="JSON config file or builtin config name for preset queries")
    parser_query.add_argument("--role", help="Filter by role (comma-separated or file)")
    parser_query.add_argument("--user", help="Filter by user (comma-separated or file)")
    parser_query.add_argument("--filter-principal", help="Exclude permissions that exist for this principal")
    parser_query.add_argument("--all-or-none", action="store_true", help="Check if ALL queried actions are allowed")
    parser_query.add_argument("--csv", help="Output results to CSV file")
    parser_query.set_defaults(func=cmd_query)

    # --- privesc ---
    parser_privesc = subparsers.add_parser("privesc", help="Analyze privilege escalation paths via AssumeRole")
    parser_privesc.add_argument("--account", required=True, help="Account ID to analyze")
    parser_privesc.add_argument("--role", help="Filter by role (comma-separated or file)")
    parser_privesc.add_argument("--user", help="Filter by user (comma-separated or file)")
    parser_privesc.add_argument("--start", help="Starting principal(s) for analysis (single, comma-separated, or file)")
    parser_privesc.add_argument("--target-policy", help="Filter to paths leading to principals with this policy (e.g., AdministratorAccess)")
    parser_privesc.add_argument("--target-action", help="Filter to paths leading to principals with this action (e.g., s3:*, iam:PassRole)")
    parser_privesc.add_argument("--cross-account", help="Additional account IDs for cross-account analysis (comma-separated). When specified, shows ONLY cross-account paths.")
    parser_privesc.set_defaults(func=cmd_privesc)

    # --- graph ---
    parser_graph = subparsers.add_parser("graph", help="Generate Neo4j graph for visualization")
    parser_graph.add_argument("--account", required=True, help="Account ID to graph")
    parser_graph.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j connection URI")
    parser_graph.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser_graph.add_argument("--neo4j-password", default="neo4j", help="Neo4j password")
    parser_graph.add_argument("--clear", action="store_true", help="Clear existing graph data before import")
    parser_graph.add_argument("--include-service-roles", action="store_true", help="Include AWS service-linked roles")
    parser_graph.add_argument("--role", help="Filter by role (comma-separated or file)")
    parser_graph.add_argument("--user", help="Filter by user (comma-separated or file)")
    parser_graph.add_argument("--start", help="Starting principal(s) for BFS traversal (single, comma-separated, or file)")
    parser_graph.add_argument("--depth", type=int, default=5, help="Max traversal depth (default: 5)")
    parser_graph.add_argument("--target-policy", help="Target principals with this policy (e.g., AdministratorAccess)")
    parser_graph.add_argument("--target-action", help="Target principals with this action (e.g., s3:*, iam:PassRole)")
    parser_graph.add_argument("--cross-account", help="Additional account IDs for cross-account analysis (comma-separated). When specified, shows ONLY cross-account paths.")
    parser_graph.set_defaults(func=cmd_graph)
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()