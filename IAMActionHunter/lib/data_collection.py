import boto3
from botocore.config import Config
import os
import json
from concurrent.futures import ThreadPoolExecutor

from IAMActionHunter.lib.statement_parser import enumerate_actions_resources_for_statements


def get_all_iam_policies(target_aws_profile):
    """
    Get all IAM policies for roles and users for the specified AWS profile
    Args: target_aws_profile (str): AWS profile to use for authentication
    Returns: None
    """

    def ensure_list(item):
        """
        Ensure that the item is a list
        Args: item (object): item to check
        returns: list: item as a list
        """
        if isinstance(item, list):
            return item
        else:
            return [item]

    def get_role_policies(role):
        role_name = role["RoleName"]
        statements = []

        # Get statetments for inline policies attached to the role
        response = iam.list_role_policies(RoleName=role_name)
        for policy_name in response["PolicyNames"]:
            statement = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]["Statement"]
            statements += ensure_list(statement)

        # Get statements for managed policies attached to the role
        response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in response["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            policy_name = policy_arn.split(":")[-1]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            statement = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"][
                "Statement"
            ]
            statements += ensure_list(statement)

        role_output = enumerate_actions_resources_for_statements(statements)

        # Save policies to file
        output_file = os.path.join(roles_output_dir, f"{role_name}.json")
        with open(output_file, "w") as f:
            json.dump(role_output, f)

    def get_user_policies(user):
        user_name = user["UserName"]
        statements = []

        # Get stetaments for inline policies attached to the user
        response = iam.list_user_policies(UserName=user_name)
        for policy_name in response["PolicyNames"]:
            statement = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]["Statement"]
            statements += ensure_list(statement)

        # Get  statements for managed policies attached to the user
        response = iam.list_attached_user_policies(UserName=user_name)
        for policy in response["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            policy_name = policy_arn.split(":")[-1]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            statement = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"][
                "Statement"
            ]
            statements += ensure_list(statement)

        # Get statements for managed policies attached to the user's groups
        response = iam.list_groups_for_user(UserName=user_name)
        for group in response["Groups"]:
            group_name = group["GroupName"]
            response = iam.list_attached_group_policies(GroupName=group_name)
            for policy in response["AttachedPolicies"]:
                policy_arn = policy["PolicyArn"]
                policy_name = policy_arn.split(":")[-1]
                version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                statement = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"][
                    "Document"
                ]["Statement"]
                statements += ensure_list(statement)
        user_output = enumerate_actions_resources_for_statements(statements)

        # Save policies to file
        output_file = os.path.join(users_output_dir, f"{user_name}.json")
        with open(output_file, "w") as f:
            json.dump(user_output, f)

    # Use the specified profile for authentication
    session = boto3.Session(profile_name=target_aws_profile)

    # Create IAM client
    config = Config(retries=dict(max_attempts=10))
    iam = session.client("iam", config=config)

    # Get AWS account number
    sts = session.client("sts")
    account_id = sts.get_caller_identity().get("Account")

    print(f"Downloading IAM policies for account {account_id}...")

    # Create the output directory using the account number
    roles_output_dir = f"actionhunter_output/{account_id}/roles"
    users_output_dir = f"actionhunter_output/{account_id}/users"
    os.makedirs(roles_output_dir, exist_ok=True)
    os.makedirs(users_output_dir, exist_ok=True)

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
        # Save policies for all roles
        for role in roles:
            executor.submit(get_role_policies, role)

        # Save policies for all users
        for user in users:
            executor.submit(get_user_policies, user)

    print(f"Finished downloading IAM policies for account {account_id}.")
    print(f"Processing files for {account_id}...")
