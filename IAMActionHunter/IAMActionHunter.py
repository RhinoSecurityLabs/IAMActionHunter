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


def process_cli_args():
    """
    Parse the command-line arguments
    returns: argparse object: command-line arguments
    """
    parser = argparse.ArgumentParser(
        description=(
            "Collect all policies for all users/roles in an AWS account and then query the policies for permissions."
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        "--profile",
        help="The name of the AWS profile to use for authentication for user/role collection.",
    )
    group.add_argument(
        "--account",
        help="Account number to query.",
    )
    parser.add_argument(
        "--query", help="Permissions to query. A string like: s3:GetObject or s3:* or s3:GetObject,s3:PutObject"
    )
    parser.add_argument(
        "--role",
        help="Filter role to query.",
    )
    parser.add_argument(
        "--user",
        help="Filter user to query.",
    )
    parser.add_argument(
        "--all-or-none",
        help="Check if all queried actions are allowed, not just some.",
        action="store_true",
        default=False,
    )
    group.add_argument(
        "--collect",
        help="Collect user and role policies for the account.",
        action="store_true",
        default=False,
    )
    group.add_argument(
        "--list",
        help="List accounts available to query.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--csv",
        help="File name for CSV report output.",
    )
    parser.add_argument(
        "--config",
        help="JSON config file for preset queries.",
    )
    args = parser.parse_args()

    if args.collect and not args.profile:
        parser.error("--collect requires --profile")
    if args.account and not (args.query or args.config):
        parser.error("--account requires --query or --config")
    return parser.parse_args()


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


def process_cli_query(permissions_json, principal_type_name, cli_args):
    """
    Iterate through all files in the roles directory
    and get the resources for the specified action
    Args: policy_file (string): file name to process
    Args: cli_args (object): command line arguments
    returns: None
    """
    try:
        query_results = {}

        # Get the resources for the queried actions
        query = cli_args.query.split(",")

        # Expand the actions for the query actions to a list
        query = Statement({"Action": query}).actions_expanded

        for action in query:
            if permissions_json.get(action):
                query_results.update({action: permissions_json.get(action)})

        # If the all-or-none flag is set, check if all actions are allowed
        if cli_args.all_or_none:
            if all(item in query_results for item in query):
                pass
            else:
                query_results = {}

        # Write CSV file if specified
        if cli_args.csv:
            process_json_and_append_to_csv(query_results, cli_args.csv, principal_type_name)

        # Print the results to the console
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


def process_config_file_query(permissions_json, config, principal_type_name, cli_args):
    """
    Iterate through all statements for a user/role policy
    and get the resources for the specified action specified in the config file
    output to the console and CSV file if specified
    Args: policy_file (string): file name to process
    Args: cli_args (object): command line arguments
    returns: None
    """
    query_results = {}
    query = config["ActionsNeeded"]

    # Expand the actions for the query actions to a list
    query = Statement({"Action": query}).actions_expanded

    for action in query:
        if permissions_json.get(action):
            query_results.update({action: permissions_json.get(action)})

    # Write CSV file if specified
    if cli_args.csv:
        process_json_and_append_to_csv(query_results, cli_args.csv, principal_type_name)

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


def get_file_list(directory):
    """
    Get a list of files in a directory
    Args: directory (string): directory to list files
    returns: list: list of files in the directory
    """
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    return files


def filter_files(files, filter):
    """
    Filter a list of files based on a filter
    Args: files (list): list of files to filter
    Args: filter (string): filter to apply to the list of files
    returns: list: list of filtered files
    """
    filtered_files = []
    for file in files:
        if filter.lower() in file.lower():
            filtered_files.append(file)
    return filtered_files


def main():
    args = process_cli_args()

    # If the list flag is set, list all accounts in the output directory
    # and exit
    if args.list:
        for account in os.listdir("actionhunter_output"):
            print(account)
        sys.exit(0)

    output_directory = f"actionhunter_output/{args.account}"

    if args.collect:
        get_all_iam_policies(args.profile)

    else:
        if not os.path.exists(output_directory):
            print(f"{args.account} does not exist. Run with --collect and --profile <aws-profile> first")
            sys.exit(1)

        role_directory = f"{output_directory}/roles"
        user_directory = f"{output_directory}/users"

        # List all files in the roles directory
        role_files = get_file_list(role_directory)

        # List all files in the users directory
        user_files = get_file_list(user_directory)

        all_files = user_files + role_files

        # Filter files based on the role or user specified
        filtered_roles = []
        filtered_users = []
        if args.role:
            for role in args.role.split(","):
                filtered_roles += filter_files(role_files, f"{role}.json")
        if args.user:
            for user in args.user.split(","):
                filtered_users += filter_files(user_files, f"{user}.json")
        if args.role or args.user:
            all_files = filtered_roles + filtered_users

        if not all_files:
            print("[-] No users or roles found for that query")
            sys.exit(1)

        if args.config:
            # Try to load config from builtin configs
            if args.config in vars(configs):
                query_config = vars(configs)[args.config]
            else:
                # Else try to load a config file
                try:
                    with open(f"configs/{args.config}.json", "r") as f:
                        query_config = json.loads(f.read())
                except FileNotFoundError:
                    try:
                        with open(args.config, "r") as f:
                            query_config = json.loads(f.read())
                    except FileNotFoundError:
                        print(f"{args.config} does not exist. Please specify a valid config file or name")
                        sys.exit(1)

        # Iterate through all files and process them
        for permission_file in all_files:
            principal_type = permission_file.split("/")[-2][:-1]
            principal_name = permission_file.split("/")[-1].split(".json")[0]

            with open(permission_file, "r") as f:
                permissions = json.load(f)

            if args.config:
                for config in query_config:
                    process_config_file_query(permissions, config, f"{principal_type}:{principal_name}", args)
            else:
                process_cli_query(permissions, f"{principal_type}:{principal_name}", args)


if __name__ == "__main__":
    main()
