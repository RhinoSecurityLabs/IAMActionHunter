"""
IAMActionHunter Graph - Neo4j visualization of AWS IAM privilege escalation paths
"""

import json
import sys
from pathlib import Path
from collections import deque

from policyuniverse.statement import Statement
from neo4j import GraphDatabase

import IAMActionHunter.configs.all as configs


# Maps privesc methods to their target types and relevant service principals
PRIVESC_TARGET_INFO = {
    "CreateNewPolicyVersion": {"type": "policy", "key_action": "iam:createpolicyversion"},
    "SetExistingDefaultPolicyVersion": {"type": "policy", "key_action": "iam:setdefaultpolicyversion"},
    "CreateEC2WithExistingIP": {"type": "passrole", "service": "ec2.amazonaws.com", "key_action": "iam:passrole"},
    "CreateAccessKey": {"type": "iam_user", "key_action": "iam:createaccesskey"},
    "CreateLoginProfile": {"type": "iam_user", "key_action": "iam:createloginprofile"},
    "UpdateLoginProfile": {"type": "iam_user", "key_action": "iam:updateloginprofile"},
    "AttachRolePolicy": {"type": "iam_role", "key_action": "iam:attachrolepolicy"},
    "PutRolePolicy": {"type": "iam_role", "key_action": "iam:putrolepolicy"},
    "UpdateRolePolicyToAssumeIt": {"type": "iam_role", "key_action": "iam:updateassumerolepolicy"},
    "PassExistingRoleToNewLambdaThenInvoke": {"type": "passrole", "service": "lambda.amazonaws.com", "key_action": "iam:passrole"},
    "PassExistingRoleToNewLambdaThenInvokeCrossAccount": {"type": "passrole", "service": "lambda.amazonaws.com", "key_action": "iam:passrole"},
    "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": {"type": "passrole", "service": "lambda.amazonaws.com", "key_action": "iam:passrole"},
    "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": {"type": "passrole", "service": "lambda.amazonaws.com", "key_action": "iam:passrole"},
    "PassExistingRoleToNewGlueDevEndpoint": {"type": "passrole", "service": "glue.amazonaws.com", "key_action": "iam:passrole"},
    "UpdateExistingGlueDevEndpoint": {"type": "glue_endpoint", "key_action": "glue:updatedevendpoint"},
    "PassExistingRoleToNewCloudFormation": {"type": "passrole", "service": "cloudformation.amazonaws.com", "key_action": "iam:passrole"},
    "PassExistingRoleToNewDataPipeline": {"type": "passrole", "service": "datapipeline.amazonaws.com", "key_action": "iam:passrole"},
    "EditExistingLambdaFunctionWithRole": {"type": "lambda_function", "key_action": "lambda:updatefunctioncode"},
    "PassExistingRoleToNewCodeStarProject": {"type": "passrole", "service": "codestar.amazonaws.com", "key_action": "iam:passrole"},
    "ModifyEC2UserData": {"type": "ec2_instance", "key_action": "ec2:modifyinstanceattribute"},
}


class IAMGraph:
    def __init__(self, uri, username, password):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
    
    def close(self):
        self.driver.close()
    
    def clear_database(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
    
    def create_indexes(self):
        with self.driver.session() as session:
            session.run("CREATE INDEX IF NOT EXISTS FOR (u:User) ON (u.name)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (r:Role) ON (r.name)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (g:Group) ON (g.name)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (res:Resource) ON (res.arn)")
    
    def create_principal_node(self, principal_type, name, account_id, attached_policies=None, inline_policies=None):
        label = principal_type.capitalize()
        arn = f"arn:aws:iam::{account_id}:{principal_type}/{name}"
        attached_list = attached_policies or []
        inline_list = inline_policies or []
        
        with self.driver.session() as session:
            session.run(
                f"""
                MERGE (p:{label} {{name: $name}})
                SET p.arn = $arn, p.account = $account,
                    p.attached_policies = $attached, p.inline_policies = $inline,
                    p.policy_count = $policy_count
                """,
                name=name, arn=arn, account=account_id,
                attached=attached_list, inline=inline_list,
                policy_count=len(attached_list) + len(inline_list)
            )
    
    def create_assume_role_edge(self, source_type, source_name, target_role, conditional=False, source_account=None, target_account=None):
        source_label = source_type.capitalize()

        # Determine edge type based on cross-account status
        if source_account and target_account and source_account != target_account:
            edge_type = "CrossAccountAssumeRole-conditional" if conditional else "CrossAccountAssumeRole"
        else:
            edge_type = "AssumeRole-conditional" if conditional else "AssumeRole"

        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (source:{source_label} {{name: $source_name}})
                MATCH (target:Role {{name: $target_name}})
                MERGE (source)-[r:`{edge_type}`]->(target)
                """,
                source_name=source_name, target_name=target_role
            )
    
    def create_resource_node(self, arn, resource_type="Resource"):
        parts = arn.split(":")
        service = parts[2] if len(parts) >= 3 else "unknown"
        with self.driver.session() as session:
            session.run(
                f"MERGE (r:{resource_type} {{arn: $arn}}) SET r.service = $service",
                arn=arn, service=service
            )
    
    def create_any_resource_node(self, resource_type="Resource"):
        with self.driver.session() as session:
            session.run(f"MERGE (r:{resource_type} {{arn: '*', name: 'Any {resource_type}'}})")
    
    def create_any_principal_node(self, principal_type):
        label = principal_type.capitalize()
        with self.driver.session() as session:
            session.run(f"MERGE (p:{label} {{name: 'ANY_{label.upper()}', arn: '*', is_wildcard: true}})")
    
    def create_privesc_edge(self, source_type, source_name, privesc_name, target_arn, target_label="Resource", conditional=False):
        source_label = source_type.capitalize()
        edge_type = f"{privesc_name}-conditional" if conditional else privesc_name
        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (source:{source_label} {{name: $source_name}})
                MATCH (target:{target_label} {{arn: $target_arn}})
                MERGE (source)-[r:`{edge_type}`]->(target)
                """,
                source_name=source_name, target_arn=target_arn
            )
    
    def create_privesc_edge_to_role(self, source_type, source_name, privesc_name, target_role_name, conditional=False):
        source_label = source_type.capitalize()
        edge_type = f"{privesc_name}-conditional" if conditional else privesc_name
        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (source:{source_label} {{name: $source_name}})
                MATCH (target:Role {{name: $target_name}})
                MERGE (source)-[r:`{edge_type}`]->(target)
                """,
                source_name=source_name, target_name=target_role_name
            )
    
    def create_privesc_edge_to_user(self, source_type, source_name, privesc_name, target_user_name, conditional=False):
        source_label = source_type.capitalize()
        edge_type = f"{privesc_name}-conditional" if conditional else privesc_name
        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (source:{source_label} {{name: $source_name}})
                MATCH (target:User {{name: $target_name}})
                MERGE (source)-[r:`{edge_type}`]->(target)
                """,
                source_name=source_name, target_name=target_user_name
            )
    
    def create_group_membership_edge(self, user_name, group_name):
        with self.driver.session() as session:
            session.run(
                """
                MATCH (u:User {name: $user_name})
                MATCH (g:Group {name: $group_name})
                MERGE (u)-[r:MemberOf]->(g)
                """,
                user_name=user_name, group_name=group_name
            )
    
    def mark_as_target(self, principal_type, name, policy_name):
        label = principal_type.capitalize()
        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (p:{label} {{name: $name}})
                SET p:Target, p.is_target = true, p.target_policy = $policy
                """,
                name=name, policy=policy_name
            )

    def mark_as_target_with_actions(self, principal_type, name, actions):
        label = principal_type.capitalize()
        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (p:{label} {{name: $name}})
                SET p:Target, p.is_target = true, p.target_actions = $actions
                """,
                name=name, actions=actions
            )


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


def analyze_trust_policy(trust_policy, account_id, source_principal_arn=None, source_principal_type=None, check_service=None):
    """
    Analyze if a trust policy allows a specific principal to assume the role.

    Args:
        trust_policy: The trust policy document
        account_id: The account ID where the role exists
        source_principal_arn: ARN of the principal trying to assume (e.g., arn:aws:iam::123:role/MyRole)
        source_principal_type: Type of principal ("role" or "user")
        check_service: If set, check if this service is trusted instead of AWS principals

    Returns:
        (is_trusted, has_conditions) tuple
    """
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    is_trusted = False
    has_conditions = False

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        assume_allowed = any(a in ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:*", "*"] for a in actions)
        if not assume_allowed:
            continue

        principal = statement.get("Principal", {})
        conditions = statement.get("Condition", {})

        if check_service:
            if isinstance(principal, dict) and "Service" in principal:
                services = principal["Service"]
                if isinstance(services, str):
                    services = [services]
                if check_service in services:
                    is_trusted = True
                    if conditions:
                        has_conditions = True
        else:
            if principal == "*":
                is_trusted = True
            elif isinstance(principal, dict):
                if "AWS" in principal:
                    aws_principals = principal["AWS"]
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if p == "*":
                            # Wildcard - anyone can assume
                            is_trusted = True
                            break
                        elif p == account_id or p == f"arn:aws:iam::{account_id}:root":
                            # Account root - any principal in the account can assume
                            is_trusted = True
                            break
                        elif source_principal_arn:
                            # Check if the specific principal is trusted
                            if p == source_principal_arn:
                                is_trusted = True
                                break
                            # Handle wildcard patterns in the trusted principal
                            if p.endswith("*") and source_principal_arn.startswith(p[:-1]):
                                is_trusted = True
                                break
            if conditions:
                has_conditions = True

    return is_trusted, has_conditions


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
        List of (role_name, has_conditions) tuples
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

        can_target = False
        for resource in allowed_resources:
            if resource == "*":
                can_target = True
                break
            if resource.endswith("*") and role_arn.startswith(resource[:-1]):
                can_target = True
                break
            if resource == role_arn:
                can_target = True
                break

        if can_target:
            is_trusted, has_conditions = analyze_trust_policy(
                trust_policy, account_id,
                source_principal_arn=source_principal_arn,
                source_principal_type=source_principal_type
            )
            if is_trusted:
                assumable.append((role_name, has_conditions))

    return assumable


def get_cross_account_assumable_roles(principal_permissions, trust_policies, source_account, target_account, source_principal_name=None, source_principal_type=None):
    """
    Check if a principal from source_account can assume roles in target_account.

    Args:
        principal_permissions: The permissions dict for the source principal
        trust_policies: Dict of role_name -> trust_policy for the target account
        source_account: The source AWS account ID
        target_account: The target AWS account ID
        source_principal_name: Name of the source principal (e.g., "MyRole")
        source_principal_type: Type of source principal ("role" or "user")

    Returns:
        List of (role_name, has_conditions) tuples for cross-account assumable roles.
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
        has_conditions = False

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

            if conditions:
                has_conditions = True

            if principal == "*":
                is_trusted = True
                break
            elif isinstance(principal, dict) and "AWS" in principal:
                aws_principals = principal["AWS"]
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if p == "*":
                        is_trusted = True
                        break
                    elif p == source_account or p == f"arn:aws:iam::{source_account}:root":
                        # Account root - any principal in the source account can assume
                        is_trusted = True
                        break
                    elif source_principal_arn:
                        # Check if the specific principal is trusted
                        if p == source_principal_arn:
                            is_trusted = True
                            break
                        # Handle wildcard patterns in the trusted principal
                        if p.endswith("*") and source_principal_arn.startswith(p[:-1]):
                            is_trusted = True
                            break

        if is_trusted:
            assumable.append((role_name, has_conditions))

    return assumable


def extract_principal_names_from_arns(arns, principal_type, account_id):
    names = []
    prefix = f"arn:aws:iam::{account_id}:{principal_type}/"
    
    for arn in arns:
        if arn == "*":
            names.append("*")
        elif arn.startswith(prefix):
            name = arn[len(prefix):]
            if "/" in name:
                name = name.split("/")[-1]
            names.append(name)
        elif arn.startswith(f"arn:aws:iam::{account_id}:") and f":{principal_type}/" in arn:
            name = arn.split(f":{principal_type}/")[-1]
            names.append(name)
    
    return names


def check_privesc_methods(principal_permissions, trust_policies, account_id, all_roles, all_users):
    found_privescs = []
    privesc_configs = configs.privescs
    
    for privesc in privesc_configs:
        privesc_name = privesc["Name"]
        actions_needed = privesc["ActionsNeeded"]
        all_or_none = privesc["AllOrNone"]
        
        expanded = Statement({"Action": actions_needed}).actions_expanded
        
        matched_actions = {}
        for action in expanded:
            action_lower = action.lower()
            action_perms = principal_permissions.get(action_lower, {})
            resources = action_perms.get("Allow_resources", [])
            if resources:
                matched_actions[action_lower] = resources
        
        has_privesc = False
        if all_or_none:
            if all(a.lower() in matched_actions for a in expanded):
                has_privesc = True
        else:
            if matched_actions:
                has_privesc = True
        
        if not has_privesc:
            continue
        
        target_info = PRIVESC_TARGET_INFO.get(privesc_name, {"type": "unknown"})
        target_type = target_info.get("type", "unknown")
        key_action = target_info.get("key_action", "").lower()
        key_resources = matched_actions.get(key_action, ["*"])
        
        if target_type == "passrole":
            service = target_info.get("service")
            passrole_resources = matched_actions.get("iam:passrole", ["*"])
            is_wildcard_passrole = "*" in passrole_resources
            
            target_roles = []
            for role_name, trust_policy in trust_policies.items():
                role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                
                can_pass = False
                if is_wildcard_passrole:
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
                    is_trusted, has_conditions = analyze_trust_policy(trust_policy, account_id, check_service=service)
                    if is_trusted:
                        target_roles.append((role_name, has_conditions))
            
            if target_roles:
                found_privescs.append((privesc_name, "role", target_roles))
        
        elif target_type == "iam_user":
            target_names = extract_principal_names_from_arns(key_resources, "user", account_id)
            if "*" in target_names:
                targets = [("ANY_USER", False)]
            else:
                targets = [(n, False) for n in target_names if n in all_users]
            if targets:
                found_privescs.append((privesc_name, "user", targets))
        
        elif target_type == "iam_role":
            target_names = extract_principal_names_from_arns(key_resources, "role", account_id)
            if "*" in target_names:
                targets = [("ANY_ROLE", False)]
            else:
                targets = [(n, False) for n in target_names if n in all_roles]
            if targets:
                found_privescs.append((privesc_name, "role", targets))
        
        elif target_type == "policy":
            if "*" in key_resources:
                found_privescs.append((privesc_name, "resource", [("*", False)]))
            else:
                found_privescs.append((privesc_name, "resource", [(r, False) for r in key_resources]))
        
        else:
            if "*" in key_resources:
                found_privescs.append((privesc_name, "resource", [("*", False)]))
            else:
                found_privescs.append((privesc_name, "resource", [(r, False) for r in key_resources]))
    
    return found_privescs


def load_principal_manifest(raw_dir, principal_type, principal_name):
    manifest_file = raw_dir / "principals" / principal_type / f"{principal_name}.json"
    if manifest_file.exists():
        with open(manifest_file, "r") as f:
            return json.load(f)
    return {}


def get_principals_with_policy(raw_dir, policy_name):
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


def is_service_linked_role(role_name):
    if role_name.startswith("AWSServiceRoleFor"):
        return True
    if role_name.startswith("AWS-"):
        return True
    return False


def parse_principal_filter(filter_arg):
    if filter_arg is None:
        return None
    filter_path = Path(filter_arg)
    if filter_path.exists():
        with open(filter_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [p.strip() for p in filter_arg.split(",") if p.strip()]


def generate_graph(args, data_dir):
    account_dir = data_dir / args.account
    raw_dir = account_dir / "raw"
    roles_dir = account_dir / "roles"
    users_dir = account_dir / "users"
    
    if not raw_dir.exists():
        print(f"No data found for account {args.account}")
        print("Run: iah collect --profile <profile>")
        sys.exit(1)
    
    role_filter = parse_principal_filter(getattr(args, 'role', None))
    user_filter = parse_principal_filter(getattr(args, 'user', None))
    start_principals = parse_principal_filter(getattr(args, 'start', None))
    max_depth = getattr(args, 'depth', 5)
    target_policy = getattr(args, 'target_policy', None)
    target_action = getattr(args, 'target_action', None)

    # Parse cross-account argument
    cross_accounts = []
    if hasattr(args, 'cross_account') and args.cross_account:
        cross_accounts = [acc.strip() for acc in args.cross_account.split(",") if acc.strip()]

    cross_account_mode = bool(cross_accounts)

    # Check for incompatible options with cross-account mode
    if cross_account_mode and (start_principals or target_policy or target_action):
        print("Error: --cross-account cannot be used with --start, --target-policy, or --target-action")
        print("Cross-account mode only supports full graph mode without filtering.")
        sys.exit(1)

    # Handle target selection (either by policy or action, not both)
    target_principals = {"users": {}, "roles": {}}
    target_type = None

    if target_policy and target_action:
        print("Error: Cannot specify both --target-policy and --target-action")
        sys.exit(1)

    if target_policy:
        target_type = "policy"
        policy_targets = get_principals_with_policy(raw_dir, target_policy)
        # Convert sets to dicts with empty action lists for consistency
        target_principals["roles"] = {r: [] for r in policy_targets["roles"]}
        target_principals["users"] = {u: [] for u in policy_targets["users"]}

        total_targets = len(target_principals["users"]) + len(target_principals["roles"])
        if total_targets == 0:
            print(f"Warning: No principals found with policy matching '{target_policy}'")
        else:
            print(f"Found {total_targets} target principals with '{target_policy}':")
            if target_principals["roles"]:
                print(f"  Roles: {', '.join(sorted(target_principals['roles'].keys()))}")
            if target_principals["users"]:
                print(f"  Users: {', '.join(sorted(target_principals['users'].keys()))}")

    try:
        graph = IAMGraph(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
    except Exception as e:
        print(f"Failed to connect to Neo4j: {e}")
        sys.exit(1)
    
    try:
        if args.clear:
            print("Clearing existing graph data...")
            graph.clear_database()
        
        print("Creating indexes...")
        graph.create_indexes()
        
        graph.create_any_resource_node("Resource")
        graph.create_any_principal_node("user")
        graph.create_any_principal_node("role")
        
        trust_policies = load_trust_policies(raw_dir)
        
        print("Loading principals...")
        
        role_permissions = {}
        skipped_roles = 0
        if roles_dir.exists():
            for perm_file in roles_dir.iterdir():
                if perm_file.suffix == ".json":
                    role_name = perm_file.stem
                    if not getattr(args, 'include_service_roles', False) and is_service_linked_role(role_name):
                        skipped_roles += 1
                        continue
                    if role_filter and role_name not in role_filter:
                        continue
                    with open(perm_file, "r") as f:
                        role_permissions[role_name] = json.load(f)
        
        user_permissions = {}
        if users_dir.exists():
            for perm_file in users_dir.iterdir():
                if perm_file.suffix == ".json":
                    user_name = perm_file.stem
                    if user_filter and user_name not in user_filter:
                        continue
                    with open(perm_file, "r") as f:
                        user_permissions[user_name] = json.load(f)
        
        all_roles = set(role_permissions.keys())
        all_users = set(user_permissions.keys())

        # Load cross-account data if specified
        cross_account_data = {}
        if cross_account_mode:
            print(f"Loading cross-account data for {len(cross_accounts)} additional accounts...")
            for target_account in cross_accounts:
                target_account_dir = data_dir / target_account
                target_raw_dir = target_account_dir / "raw"
                target_roles_dir = target_account_dir / "roles"

                if not target_raw_dir.exists():
                    print(f"  Warning: No data found for cross-account {target_account}, skipping")
                    continue

                # Load trust policies for target account
                target_trust_policies = load_trust_policies(target_raw_dir)

                # Load role permissions for target account
                target_role_permissions = {}
                if target_roles_dir.exists():
                    for perm_file in target_roles_dir.iterdir():
                        if perm_file.suffix == ".json":
                            role_name = perm_file.stem
                            with open(perm_file, "r") as f:
                                target_role_permissions[role_name] = json.load(f)

                cross_account_data[target_account] = {
                    "trust_policies": target_trust_policies,
                    "role_permissions": target_role_permissions,
                    "raw_dir": target_raw_dir
                }
                print(f"  Loaded {target_account}: {len(target_role_permissions)} roles")

        # Handle target_action after loading permissions
        if target_action:
            target_type = "action"
            target_principals = get_principals_with_action(target_action, role_permissions, user_permissions)
            total_targets = len(target_principals["users"]) + len(target_principals["roles"])
            if total_targets == 0:
                print(f"Warning: No principals found with action matching '{target_action}'")
            else:
                print(f"Found {total_targets} target principals with '{target_action}':")
                if target_principals["roles"]:
                    role_list = sorted(target_principals['roles'].keys())
                    if len(role_list) > 10:
                        print(f"  Roles: {', '.join(role_list[:10])}...")
                        print(f"    ... and {len(role_list) - 10} more")
                    else:
                        print(f"  Roles: {', '.join(role_list)}")
                if target_principals["users"]:
                    user_list = sorted(target_principals['users'].keys())
                    if len(user_list) > 10:
                        print(f"  Users: {', '.join(user_list[:10])}...")
                        print(f"    ... and {len(user_list) - 10} more")
                    else:
                        print(f"  Users: {', '.join(user_list)}")

        if start_principals:
            invalid_principals = []
            for sp in start_principals:
                if sp not in all_roles and sp not in all_users:
                    invalid_principals.append(sp)
            if invalid_principals:
                print(f"Error: Start principal(s) not found in roles or users: {', '.join(invalid_principals)}")
                sys.exit(1)
            if len(start_principals) == 1:
                print(f"Building graph from starting point: {start_principals[0]}")
            else:
                print(f"Building graph from {len(start_principals)} starting points: {', '.join(start_principals[:5])}{'...' if len(start_principals) > 5 else ''}")
        
        print("Creating principal nodes...")
        for role_name in role_permissions:
            manifest = load_principal_manifest(raw_dir, "roles", role_name)
            managed_arns = manifest.get("managed", [])
            attached = [arn.split("/")[-1] for arn in managed_arns]
            inline = manifest.get("inline", [])
            graph.create_principal_node("role", role_name, args.account, attached_policies=attached, inline_policies=inline)
        
        for user_name in user_permissions:
            manifest = load_principal_manifest(raw_dir, "users", user_name)
            managed_arns = manifest.get("managed", [])
            attached = [arn.split("/")[-1] for arn in managed_arns]
            inline = manifest.get("inline", [])
            graph.create_principal_node("user", user_name, args.account, attached_policies=attached, inline_policies=inline)
        
        if target_policy or target_action:
            print("Marking target principals with :Target label...")
            for role_name in target_principals["roles"]:
                if role_name in role_permissions:
                    if target_type == "policy":
                        graph.mark_as_target("role", role_name, target_policy)
                    elif target_type == "action":
                        actions = target_principals["roles"][role_name]
                        graph.mark_as_target_with_actions("role", role_name, actions)
            for user_name in target_principals["users"]:
                if user_name in user_permissions:
                    if target_type == "policy":
                        graph.mark_as_target("user", user_name, target_policy)
                    elif target_type == "action":
                        actions = target_principals["users"][user_name]
                        graph.mark_as_target_with_actions("user", user_name, actions)
        
        groups_seen = set()
        group_policies = {}
        groups_dir = raw_dir / "principals" / "groups"
        
        if groups_dir.exists():
            for manifest_file in groups_dir.iterdir():
                if manifest_file.suffix == ".json":
                    group_name = manifest_file.stem
                    with open(manifest_file, "r") as f:
                        manifest = json.load(f)
                    managed_arns = manifest.get("managed", [])
                    attached = [arn.split("/")[-1] for arn in managed_arns]
                    inline = manifest.get("inline", [])
                    group_policies[group_name] = {"attached": attached, "inline": inline}
        
        users_principals_dir = raw_dir / "principals" / "users"
        if users_principals_dir.exists():
            for manifest_file in users_principals_dir.iterdir():
                if manifest_file.suffix == ".json":
                    user_name = manifest_file.stem
                    if user_name not in user_permissions:
                        continue
                    manifest = load_principal_manifest(raw_dir, "users", user_name)
                    for group_name in manifest.get("groups", []):
                        if group_name not in groups_seen:
                            gp = group_policies.get(group_name, {"attached": [], "inline": []})
                            graph.create_principal_node("group", group_name, args.account,
                                                       attached_policies=gp["attached"],
                                                       inline_policies=gp["inline"])
                            groups_seen.add(group_name)
                        graph.create_group_membership_edge(user_name, group_name)
        
        resource_arns = set()
        assume_role_count = 0
        privesc_edge_count = 0
        
        # === TARGET MODE: BFS with path finding ===
        if start_principals and (target_policy or target_action) and (target_principals["users"] or target_principals["roles"]):
            target_desc = target_policy if target_policy else target_action
            start_desc = start_principals[0] if len(start_principals) == 1 else f"{len(start_principals)} starting points"
            print(f"\nBuilding paths from {start_desc} to targets with '{target_desc}'...")
            
            # Load ALL roles for pathfinding (including service-linked)
            all_role_permissions = {}
            all_user_permissions = {}
            
            if roles_dir.exists():
                for perm_file in roles_dir.iterdir():
                    if perm_file.suffix == ".json":
                        rn = perm_file.stem
                        with open(perm_file, "r") as f:
                            all_role_permissions[rn] = json.load(f)
            
            if users_dir.exists():
                for perm_file in users_dir.iterdir():
                    if perm_file.suffix == ".json":
                        un = perm_file.stem
                        with open(perm_file, "r") as f:
                            all_user_permissions[un] = json.load(f)
            
            all_roles_full = set(all_role_permissions.keys())
            all_users_full = set(all_user_permissions.keys())
            
            # Build complete adjacency list
            print("  Building adjacency list...")
            adjacency = {p: [] for p in list(all_role_permissions.keys()) + list(all_user_permissions.keys())}
            reverse_adj = {p: [] for p in adjacency}
            
            for rn, perms in all_role_permissions.items():
                perms_lower = {k.lower(): v for k, v in perms.items()}

                # AssumeRole edges
                for target_role, has_cond in get_assumable_roles(perms_lower, trust_policies, args.account, rn, "role"):
                    if target_role != rn and target_role in all_role_permissions:
                        adjacency[rn].append((target_role, "AssumeRole", has_cond))
                        reverse_adj[target_role].append((rn, "AssumeRole", has_cond))
                
                # PrivEsc edges
                for pe_name, ttype, targets in check_privesc_methods(perms_lower, trust_policies, args.account, all_roles_full, all_users_full):
                    for target, has_cond in targets:
                        if ttype == "role" and target != rn and target in all_role_permissions:
                            adjacency[rn].append((target, pe_name, has_cond))
                            reverse_adj[target].append((rn, pe_name, has_cond))
                        elif ttype == "user" and target in all_user_permissions:
                            adjacency[rn].append((target, pe_name, has_cond))
                            reverse_adj[target].append((rn, pe_name, has_cond))
            
            for un, perms in all_user_permissions.items():
                perms_lower = {k.lower(): v for k, v in perms.items()}

                for target_role, has_cond in get_assumable_roles(perms_lower, trust_policies, args.account, un, "user"):
                    if target_role in all_role_permissions:
                        adjacency[un].append((target_role, "AssumeRole", has_cond))
                        reverse_adj[target_role].append((un, "AssumeRole", has_cond))
                
                for pe_name, ttype, targets in check_privesc_methods(perms_lower, trust_policies, args.account, all_roles_full, all_users_full):
                    for target, has_cond in targets:
                        if ttype == "role" and target in all_role_permissions:
                            adjacency[un].append((target, pe_name, has_cond))
                            reverse_adj[target].append((un, pe_name, has_cond))
                        elif ttype == "user" and target != un and target in all_user_permissions:
                            adjacency[un].append((target, pe_name, has_cond))
                            reverse_adj[target].append((un, pe_name, has_cond))
            
            total_edges = sum(len(v) for v in adjacency.values())
            print(f"  Built adjacency list: {len(adjacency)} principals, {total_edges} edges")
            
            # Reverse BFS from targets to calculate distances
            print("  Calculating distances to targets...")
            distance_to_target = {}
            reverse_queue = deque()
            
            for role_name in target_principals["roles"]:
                if role_name in all_role_permissions:
                    distance_to_target[role_name] = 0
                    reverse_queue.append((role_name, 0))
            for user_name in target_principals["users"]:
                if user_name in all_user_permissions:
                    distance_to_target[user_name] = 0
                    reverse_queue.append((user_name, 0))
            
            while reverse_queue:
                current, dist = reverse_queue.popleft()
                for neighbor, _, _ in reverse_adj.get(current, []):
                    if neighbor not in distance_to_target:
                        distance_to_target[neighbor] = dist + 1
                        reverse_queue.append((neighbor, dist + 1))
            
            print(f"  {len(distance_to_target)} nodes can reach targets")
            if distance_to_target:
                max_dist = max(distance_to_target.values())
                print(f"  Max distance to target: {max_dist} hops")
            
            # Debug output
            all_targets = target_principals.get("roles", set()) | target_principals.get("users", set())
            print(f"\n  DEBUG: {len(all_targets)} total targets")

            # Show debug info for each start principal
            reachable_starts = []
            unreachable_starts = []
            for sp in start_principals:
                start_dist = distance_to_target.get(sp, float('inf'))
                start_edges = adjacency.get(sp, [])
                if len(start_principals) <= 3:
                    print(f"  DEBUG: {sp} has {len(start_edges)} edges (distance: {start_dist})")
                if start_dist != float('inf'):
                    reachable_starts.append(sp)
                else:
                    unreachable_starts.append(sp)

            if len(start_principals) > 3:
                print(f"  DEBUG: {len(reachable_starts)} start principals can reach targets, {len(unreachable_starts)} cannot")

            # For single principal, show detailed edge info
            if len(start_principals) == 1:
                start_principal = start_principals[0]
                start_edges = adjacency.get(start_principal, [])
                # Group edges by destination distance
                edges_by_dist = {}
                for neighbor, edge_type, _ in start_edges:
                    nd = distance_to_target.get(neighbor, float('inf'))
                    if nd not in edges_by_dist:
                        edges_by_dist[nd] = []
                    edges_by_dist[nd].append((neighbor, edge_type))

                for dist in sorted(d for d in edges_by_dist.keys() if d != float('inf')):
                    edges = edges_by_dist[dist]
                    print(f"    Distance {dist}: {len(edges)} edges")
                    for n, e in edges[:5]:
                        marker = " *** TARGET ***" if n in all_targets else ""
                        print(f"      -> {n} via {e}{marker}")
                    if len(edges) > 5:
                        print(f"      ... and {len(edges) - 5} more")

                unreachable = edges_by_dist.get(float('inf'), [])
                print(f"    Distance unreachable: {len(unreachable)} edges")

                # Show intermediate nodes
                print(f"\n  DEBUG: Intermediate nodes (distance 1-2) with paths to targets:")
                for node, dist in sorted(distance_to_target.items(), key=lambda x: x[1]):
                    if 0 < dist <= 2:
                        node_edges = adjacency.get(node, [])
                        toward = [(n, e) for n, e, _ in node_edges if distance_to_target.get(n, float('inf')) < dist]
                        if toward:
                            print(f"    {node} (dist {dist}): {len(toward)} edges toward targets")
                            for n, e in toward[:3]:
                                marker = " *** TARGET ***" if n in all_targets else ""
                                print(f"      -> {n} via {e}{marker}")

            if unreachable_starts:
                if len(unreachable_starts) <= 3:
                    print(f"\n  Warning: These start principals cannot reach any targets: {', '.join(unreachable_starts)}")
                else:
                    print(f"\n  Warning: {len(unreachable_starts)} start principals cannot reach any targets")

            if reachable_starts:
                # Forward BFS: create ALL edges where destination can reach a target
                print(f"\n  Building graph with ALL paths to targets...")
                visited = set()
                edges_created = set()
                queue = deque()

                # Initialize queue with all reachable start principals
                for sp in reachable_starts:
                    start_type = "role" if sp in all_roles_full else "user"
                    queue.append((sp, start_type))
                    visited.add(sp)
                
                while queue:
                    current_name, current_type = queue.popleft()
                    current_dist = distance_to_target.get(current_name, float('inf'))
                    
                    if current_dist == 0:
                        continue
                    
                    for neighbor, edge_type, conditional in adjacency.get(current_name, []):
                        if neighbor == current_name:
                            continue
                        
                        neighbor_dist = distance_to_target.get(neighbor, float('inf'))
                        if neighbor_dist == float('inf'):
                            continue
                        
                        edge_key = (current_name, neighbor, edge_type)
                        if edge_key in edges_created:
                            continue
                        edges_created.add(edge_key)
                        
                        neighbor_type = "role" if neighbor in all_roles_full else "user"
                        
                        # Create node if needed
                        if neighbor not in visited:
                            manifest = load_principal_manifest(raw_dir, "roles" if neighbor_type == "role" else "users", neighbor)
                            managed_arns = manifest.get("managed", [])
                            att = [arn.split("/")[-1] for arn in managed_arns]
                            inl = manifest.get("inline", [])
                            graph.create_principal_node(neighbor_type, neighbor, args.account, attached_policies=att, inline_policies=inl)
                            if neighbor in all_targets:
                                if target_type == "policy":
                                    graph.mark_as_target(neighbor_type, neighbor, target_policy)
                                elif target_type == "action":
                                    actions = target_principals["roles"].get(neighbor, []) if neighbor_type == "role" else target_principals["users"].get(neighbor, [])
                                    graph.mark_as_target_with_actions(neighbor_type, neighbor, actions)
                        
                        # Create edge
                        if edge_type == "AssumeRole":
                            graph.create_assume_role_edge(current_type, current_name, neighbor, conditional=conditional)
                            assume_role_count += 1
                        elif neighbor_type == "role":
                            graph.create_privesc_edge_to_role(current_type, current_name, edge_type, neighbor, conditional=conditional)
                            privesc_edge_count += 1
                        else:
                            graph.create_privesc_edge_to_user(current_type, current_name, edge_type, neighbor, conditional=conditional)
                            privesc_edge_count += 1
                        
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append((neighbor, neighbor_type))
                
                print(f"  Visited {len(visited)} principals, created {len(edges_created)} edges")
        
        # === REGULAR START MODE (no target policy) ===
        elif start_principals:
            if len(start_principals) == 1:
                print(f"Performing BFS traversal from {start_principals[0]}...")
            else:
                print(f"Performing BFS traversal from {len(start_principals)} starting principals...")
            visited = set()
            queue = deque()

            # Initialize queue with all start principals
            for sp in start_principals:
                if sp in all_roles:
                    queue.append((sp, "role", 0))
                else:
                    queue.append((sp, "user", 0))
                visited.add(sp)
            
            while queue:
                current_name, current_type, depth = queue.popleft()
                if depth >= max_depth:
                    continue
                
                perms = role_permissions.get(current_name, {}) if current_type == "role" else user_permissions.get(current_name, {})
                perms_lower = {k.lower(): v for k, v in perms.items()}

                for target_role, has_cond in get_assumable_roles(perms_lower, trust_policies, args.account, current_name, current_type):
                    if target_role == current_name or target_role not in role_permissions:
                        continue
                    if target_role not in visited:
                        graph.create_assume_role_edge(current_type, current_name, target_role, conditional=has_cond)
                        assume_role_count += 1
                        visited.add(target_role)
                        queue.append((target_role, "role", depth + 1))
                
                for pe_name, ttype, targets in check_privesc_methods(perms_lower, trust_policies, args.account, all_roles, all_users):
                    for target, has_cond in targets:
                        if ttype == "role" and target == current_name:
                            continue
                        if ttype == "user" and target == current_name:
                            continue
                        
                        if ttype == "role" and target not in visited and target in role_permissions:
                            graph.create_privesc_edge_to_role(current_type, current_name, pe_name, target, conditional=has_cond)
                            privesc_edge_count += 1
                            visited.add(target)
                            queue.append((target, "role", depth + 1))
                        elif ttype == "user" and target not in visited and target in user_permissions:
                            graph.create_privesc_edge_to_user(current_type, current_name, pe_name, target, conditional=has_cond)
                            privesc_edge_count += 1
                            visited.add(target)
                            queue.append((target, "user", depth + 1))
                        elif ttype == "resource":
                            if target != "*":
                                resource_arns.add(target)
                            graph.create_privesc_edge(current_type, current_name, pe_name, target if target != "*" else "*", 
                                                     target_label="Resource", conditional=has_cond)
                            privesc_edge_count += 1
            
            print(f"  Visited {len(visited)} principals")
        
        # === FULL GRAPH MODE ===
        else:
            if cross_account_mode:
                # Cross-account mode: only show cross-account edges
                print("Creating cross-account AssumeRole edges...")

                # Create nodes for target account roles
                for target_account, target_data in cross_account_data.items():
                    target_role_perms = target_data["role_permissions"]
                    target_raw_dir = target_data["raw_dir"]
                    for target_role_name in target_role_perms:
                        manifest = load_principal_manifest(target_raw_dir, "roles", target_role_name)
                        managed_arns = manifest.get("managed", [])
                        attached = [arn.split("/")[-1] for arn in managed_arns]
                        inline = manifest.get("inline", [])
                        graph.create_principal_node("role", target_role_name, target_account, attached_policies=attached, inline_policies=inline)

                # Check cross-account AssumeRole from roles in primary account
                for role_name, perms in role_permissions.items():
                    perms_lower = {k.lower(): v for k, v in perms.items()}
                    for target_account, target_data in cross_account_data.items():
                        target_trust_policies = target_data["trust_policies"]
                        target_role_perms = target_data["role_permissions"]
                        for target_role, has_cond in get_cross_account_assumable_roles(
                            perms_lower, target_trust_policies, args.account, target_account, role_name, "role"
                        ):
                            if target_role in target_role_perms:
                                graph.create_assume_role_edge("role", role_name, target_role, conditional=has_cond,
                                                            source_account=args.account, target_account=target_account)
                                assume_role_count += 1

                # Check cross-account AssumeRole from users in primary account
                for user_name, perms in user_permissions.items():
                    perms_lower = {k.lower(): v for k, v in perms.items()}
                    for target_account, target_data in cross_account_data.items():
                        target_trust_policies = target_data["trust_policies"]
                        target_role_perms = target_data["role_permissions"]
                        for target_role, has_cond in get_cross_account_assumable_roles(
                            perms_lower, target_trust_policies, args.account, target_account, user_name, "user"
                        ):
                            if target_role in target_role_perms:
                                graph.create_assume_role_edge("user", user_name, target_role, conditional=has_cond,
                                                            source_account=args.account, target_account=target_account)
                                assume_role_count += 1

                print(f"  Created {assume_role_count} cross-account edges")
            else:
                # Same-account mode: show same-account edges
                print("Creating AssumeRole edges...")
                for role_name, perms in role_permissions.items():
                    perms_lower = {k.lower(): v for k, v in perms.items()}
                    for target_role, has_cond in get_assumable_roles(perms_lower, trust_policies, args.account, role_name, "role"):
                        if role_name != target_role and target_role in role_permissions:
                            graph.create_assume_role_edge("role", role_name, target_role, conditional=has_cond)
                            assume_role_count += 1

                for user_name, perms in user_permissions.items():
                    perms_lower = {k.lower(): v for k, v in perms.items()}
                    for target_role, has_cond in get_assumable_roles(perms_lower, trust_policies, args.account, user_name, "user"):
                        if target_role in role_permissions:
                            graph.create_assume_role_edge("user", user_name, target_role, conditional=has_cond)
                            assume_role_count += 1

                print("Creating PrivEsc edges...")
                for role_name, perms in role_permissions.items():
                    perms_lower = {k.lower(): v for k, v in perms.items()}
                    for pe_name, ttype, targets in check_privesc_methods(perms_lower, trust_policies, args.account, all_roles, all_users):
                        for target, has_cond in targets:
                            if ttype == "role" and target == role_name:
                                continue
                            if ttype == "role":
                                graph.create_privesc_edge_to_role("role", role_name, pe_name, target, conditional=has_cond)
                                privesc_edge_count += 1
                            elif ttype == "user":
                                graph.create_privesc_edge_to_user("role", role_name, pe_name, target, conditional=has_cond)
                                privesc_edge_count += 1
                            elif ttype == "resource":
                                if target != "*":
                                    resource_arns.add(target)
                                graph.create_privesc_edge("role", role_name, pe_name, target if target != "*" else "*",
                                                         target_label="Resource", conditional=has_cond)
                                privesc_edge_count += 1

                for user_name, perms in user_permissions.items():
                    perms_lower = {k.lower(): v for k, v in perms.items()}
                    for pe_name, ttype, targets in check_privesc_methods(perms_lower, trust_policies, args.account, all_roles, all_users):
                        for target, has_cond in targets:
                            if ttype == "user" and target == user_name:
                                continue
                            if ttype == "role":
                                graph.create_privesc_edge_to_role("user", user_name, pe_name, target, conditional=has_cond)
                                privesc_edge_count += 1
                            elif ttype == "user":
                                graph.create_privesc_edge_to_user("user", user_name, pe_name, target, conditional=has_cond)
                                privesc_edge_count += 1
                            elif ttype == "resource":
                                if target != "*":
                                    resource_arns.add(target)
                                graph.create_privesc_edge("user", user_name, pe_name, target if target != "*" else "*",
                                                         target_label="Resource", conditional=has_cond)
                                privesc_edge_count += 1
        
        print(f"Creating {len(resource_arns)} resource nodes...")
        for arn in resource_arns:
            graph.create_resource_node(arn)
        
        print(f"\nGraph created successfully!")
        print(f"  Roles: {len(role_permissions)} (skipped {skipped_roles} service-linked)")
        print(f"  Users: {len(user_permissions)}")
        print(f"  Groups: {len(groups_seen)}")
        print(f"  Resources: {len(resource_arns)}")
        print(f"  AssumeRole edges: {assume_role_count}")
        print(f"  PrivEsc edges: {privesc_edge_count}")
        
        print(f"\nOpen Neo4j Browser at http://localhost:7474")
        if start_principals and (target_policy or target_action):
            example_start = start_principals[0]
            print(f"  MATCH p=(n {{name: '{example_start}'}})-[*]->(t:Target) RETURN p")
            if len(start_principals) > 1:
                print(f"  (or use other start principals: {', '.join(start_principals[1:4])}{'...' if len(start_principals) > 4 else ''})")
        elif start_principals:
            example_start = start_principals[0]
            print(f"  MATCH p=(n {{name: '{example_start}'}})-[*1..{max_depth}]->() RETURN p")
            if len(start_principals) > 1:
                print(f"  (or use other start principals: {', '.join(start_principals[1:4])}{'...' if len(start_principals) > 4 else ''})")
        else:
            print("  MATCH p=()-[]->() RETURN p LIMIT 100")
        
    finally:
        graph.close()