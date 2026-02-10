import boto3
from botocore.config import Config
from botocore.exceptions import NoCredentialsError
import os
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from IAMActionHunter.lib.statement_parser import enumerate_actions_resources_for_statements

data_dir = Path.home() / ".iamactionhunter"
data_dir.mkdir(exist_ok=True)


def safe_filename(name):
    """Convert a string to a safe filename by replacing problematic characters."""
    return name.replace("/", "_").replace(":", "_")


def get_all_iam_policies(target_aws_profile, account_id):
    """
    Get all IAM policies for roles and users for the specified AWS profile.
    - If raw policies don't exist, fetch from AWS and store them
    - Transform raw policies from filesystem into expanded permissions
    Args: target_aws_profile (str): AWS profile to use for authentication
    Returns: None
    """

    def ensure_list(item):
        if isinstance(item, list):
            return item
        else:
            return [item]

    def save_policy(policy_type, principal_type, principal_name, policy_name, policy_document):
        """Save a policy document to the appropriate location."""
        if policy_type == "inline":
            policy_dir = raw_dir / "policies" / "inline" / principal_type
            policy_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{principal_name}_{policy_name}.json"
        else:  # managed
            policy_dir = raw_dir / "policies" / "managed"
            policy_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{safe_filename(policy_name)}.json"
        
        policy_file = policy_dir / filename
        if not policy_file.exists():
            with open(policy_file, "w") as f:
                json.dump(policy_document, f, indent=2)

    def get_role_policies(role):
        role_name = role["RoleName"]
        manifest = {"inline": [], "managed": [], "trust": None}

        # Store trust policy
        if "AssumeRolePolicyDocument" in role:
            trust_dir = raw_dir / "policies" / "trust"
            trust_dir.mkdir(parents=True, exist_ok=True)
            trust_file = trust_dir / f"{role_name}.json"
            with open(trust_file, "w") as f:
                json.dump(role["AssumeRolePolicyDocument"], f, indent=2)
            manifest["trust"] = role_name

        # Get inline policies
        response = iam.list_role_policies(RoleName=role_name)
        for policy_name in response["PolicyNames"]:
            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
            save_policy("inline", "roles", role_name, policy_name, policy_doc)
            manifest["inline"].append(policy_name)

        # Get managed policies
        response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in response["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
            save_policy("managed", "roles", role_name, policy_arn, policy_doc)
            manifest["managed"].append(policy_arn)

        # Save role manifest
        manifest_file = raw_dir / "principals" / "roles" / f"{role_name}.json"
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

    def get_user_policies(user):
        user_name = user["UserName"]
        manifest = {"inline": [], "managed": [], "groups": []}

        # Get inline policies
        response = iam.list_user_policies(UserName=user_name)
        for policy_name in response["PolicyNames"]:
            policy_doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
            save_policy("inline", "users", user_name, policy_name, policy_doc)
            manifest["inline"].append(policy_name)

        # Get managed policies
        response = iam.list_attached_user_policies(UserName=user_name)
        for policy in response["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
            save_policy("managed", "users", user_name, policy_arn, policy_doc)
            manifest["managed"].append(policy_arn)

        # Get groups
        groups_response = iam.list_groups_for_user(UserName=user_name)
        for group in groups_response["Groups"]:
            group_name = group["GroupName"]
            manifest["groups"].append(group_name)
            
            # Get group policies (stored separately)
            get_group_policies(group_name)

        # Save user manifest
        manifest_file = raw_dir / "principals" / "users" / f"{user_name}.json"
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

    def get_group_policies(group_name):
        """Get and store policies for a group."""
        manifest_file = raw_dir / "principals" / "groups" / f"{group_name}.json"
        if manifest_file.exists():
            return  # Already processed
        
        manifest = {"inline": [], "managed": []}

        # Get inline policies
        response = iam.list_group_policies(GroupName=group_name)
        for policy_name in response["PolicyNames"]:
            policy_doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
            save_policy("inline", "groups", group_name, policy_name, policy_doc)
            manifest["inline"].append(policy_name)

        # Get managed policies
        response = iam.list_attached_group_policies(GroupName=group_name)
        for policy in response["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
            save_policy("managed", "groups", group_name, policy_arn, policy_doc)
            manifest["managed"].append(policy_arn)

        # Save group manifest
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)


    account_dir = data_dir / account_id
    raw_dir = account_dir / "raw"
    roles_output_dir = account_dir / "roles"
    users_output_dir = account_dir / "users"

    # Check if raw policies already exist
    raw_exists = (raw_dir / "principals").exists()

    if raw_exists:
        print(f"Raw policies already exist for account {account_id}. Skipping API collection.")
    else:
        print(f"Collecting IAM policies for account {account_id}...")
        if target_aws_profile:
            session = boto3.Session(profile_name=target_aws_profile)
        else:
            session = boto3.Session()

        config = Config(retries=dict(max_attempts=10))
        iam = session.client("iam", config=config)

        sts = session.client("sts")
        try:
            account_id = sts.get_caller_identity().get("Account")
        except NoCredentialsError:
            print("No valid AWS credentials found. Please configure your AWS credentials.")
            return

        # Paginate through all roles
        roles = []
        marker = None
        while True:
            if marker:
                response = iam.list_roles(Marker=marker)
            else:
                response = iam.list_roles()
            roles.extend(response["Roles"])
            if response["IsTruncated"]:
                marker = response["Marker"]
            else:
                break

        # Paginate through all users
        users = []
        marker = None
        while True:
            if marker:
                response = iam.list_users(Marker=marker)
            else:
                response = iam.list_users()
            users.extend(response["Users"])
            if response["IsTruncated"]:
                marker = response["Marker"]
            else:
                break

        with ThreadPoolExecutor(max_workers=10) as executor:
            for role in roles:
                executor.submit(get_role_policies, role)
            for user in users:
                executor.submit(get_user_policies, user)

        print(f"Finished collecting IAM policies for account {account_id}.")

    # Transform raw policies into expanded permissions
    print(f"Processing policies for account {account_id}...")

    os.makedirs(roles_output_dir, exist_ok=True)
    os.makedirs(users_output_dir, exist_ok=True)

    def load_policy(policy_type, principal_type, principal_name, policy_name):
        """Load a policy document from the appropriate location."""
        if policy_type == "inline":
            policy_file = raw_dir / "policies" / "inline" / principal_type / f"{principal_name}_{policy_name}.json"
        else:  # managed
            policy_file = raw_dir / "policies" / "managed" / f"{safe_filename(policy_name)}.json"
        
        if policy_file.exists():
            with open(policy_file, "r") as f:
                return json.load(f)
        return None

    def collect_statements_for_principal(principal_type, principal_name):
        """Collect all statements for a principal from their manifest."""
        manifest_file = raw_dir / "principals" / principal_type / f"{principal_name}.json"
        if not manifest_file.exists():
            return []

        with open(manifest_file, "r") as f:
            manifest = json.load(f)

        statements = []

        # Load inline policies
        for policy_name in manifest.get("inline", []):
            policy_doc = load_policy("inline", principal_type, principal_name, policy_name)
            if policy_doc and "Statement" in policy_doc:
                statements += ensure_list(policy_doc["Statement"])

        # Load managed policies
        for policy_arn in manifest.get("managed", []):
            policy_doc = load_policy("managed", principal_type, principal_name, policy_arn)
            if policy_doc and "Statement" in policy_doc:
                statements += ensure_list(policy_doc["Statement"])

        # For users, also load group policies
        if principal_type == "users":
            for group_name in manifest.get("groups", []):
                group_statements = collect_statements_for_principal("groups", group_name)
                statements += group_statements

        return statements

    # Process roles
    roles_principals_dir = raw_dir / "principals" / "roles"
    if roles_principals_dir.exists():
        for manifest_file in roles_principals_dir.iterdir():
            if manifest_file.suffix == ".json":
                role_name = manifest_file.stem
                statements = collect_statements_for_principal("roles", role_name)
                permissions = enumerate_actions_resources_for_statements(statements)
                output_file = roles_output_dir / f"{role_name}.json"
                with open(output_file, "w") as f:
                    json.dump(permissions, f)

    # Process users
    users_principals_dir = raw_dir / "principals" / "users"
    if users_principals_dir.exists():
        for manifest_file in users_principals_dir.iterdir():
            if manifest_file.suffix == ".json":
                user_name = manifest_file.stem
                statements = collect_statements_for_principal("users", user_name)
                permissions = enumerate_actions_resources_for_statements(statements)
                output_file = users_output_dir / f"{user_name}.json"
                with open(output_file, "w") as f:
                    json.dump(permissions, f)

    print(f"Finished processing policies for account {account_id}.")