from policyuniverse.statement import Statement
from policy_sentry.querying.actions import get_action_data


class ExtendedStatement(Statement):
    """
    Extends the Statement class to add the notresources and conditions properties
    """

    @property
    def notresources(self):
        # If the statement has NotResource, add a notresources attribute to the PU statement object
        if "NotResource" in self.statement:
            if isinstance(self.statement.get("NotResource"), str):
                return set([self.statement.get("NotResource")])
            return set(self.statement.get("NotResource"))
        else:
            return set()

    @property
    def conditions(self):
        # Add a conditions attribute to the PU statement object
        return self.statement.get("Condition") or {}


def convert_sets_to_lists(obj):
    """
    Converts sets to lists in a dictionary
    Args: obj (dict): a dictionary object
    returns: dict: a dictionary object with sets converted to lists
    """
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {key: convert_sets_to_lists(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(element) for element in obj]
    else:
        return obj


# Cross-service mappings for known exceptions where action service != resource service
CROSS_SERVICE_RESOURCE_MAPPINGS = {
    'sts': {'iam'},  # sts:AssumeRole uses iam role ARNs
}


def get_valid_resource_services_for_action(action):
    """
    Get the valid resource service prefixes for a given action using policy_sentry.
    Returns a tuple: (set of service prefixes, wildcard_only, found_in_policy_sentry)
    - service prefixes: e.g., {'iam'} for sts:AssumeRole
    - wildcard_only: True if action only supports "*" (no resource-level permissions)
    - found_in_policy_sentry: True if action was found in policy_sentry database
    Args: action (str): IAM action like "s3:GetObject" or "sts:AssumeRole"
    returns: tuple: (set or None, bool, bool)
    """
    if ":" not in action:
        return None, False, False

    service, action_name = action.split(":", 1)
    service = service.lower()

    try:
        action_data = get_action_data(service, action_name)
    except Exception:
        return None, False, False

    if not action_data or service not in action_data:
        return None, False, False

    action_info = action_data[service]
    if not action_info:
        return None, False, False

    # action_info is a list of action details
    valid_services = set()
    has_specific_resources = False

    for item in action_info:
        resource_arn_format = item.get("resource_arn_format", "")
        # If resource is "*" or empty, action doesn't support resource-level permissions
        if not resource_arn_format or resource_arn_format == "*":
            continue
        # Extract service from ARN format: arn:partition:SERVICE:region:account:resource
        arn_parts = resource_arn_format.split(":")
        if len(arn_parts) >= 3:
            valid_services.add(arn_parts[2].lower())
            has_specific_resources = True

    if not has_specific_resources:
        # Action only supports wildcard "*" resources
        return set(), True, True

    return valid_services, False, True


def get_service_from_arn(arn):
    """
    Extract service name from ARN (e.g., 's3' from 'arn:aws:s3:::bucket')
    Args: arn (str): AWS ARN string
    returns: str or None: service prefix or None if wildcard/invalid
    """
    if arn == "*":
        return None
    parts = arn.split(":")
    if len(parts) >= 3:
        return parts[2].lower()
    return None


def get_service_from_action(action):
    """
    Extract service name from action (e.g., 's3' from 's3:GetObject')
    Args: action (str): IAM action string
    returns: str or None: service prefix
    """
    if ":" in action:
        return action.split(":")[0].lower()
    return None


# Cache for action -> (valid_services, wildcard_only, found) mapping
_action_service_cache = {}


def is_resource_valid_for_action(action, resource):
    """
    Check if a resource ARN is valid for a given action.
    Args: action (str): IAM action like "s3:GetObject"
    Args: resource (str): Resource ARN like "arn:aws:s3:::bucket"
    returns: bool: True if the resource is valid for the action
    """
    # Wildcard resources are always valid
    if resource == "*":
        return True

    resource_service = get_service_from_arn(resource)
    if resource_service is None:
        return True  # Can't determine, assume valid

    # Check cache first
    action_lower = action.lower()
    if action_lower not in _action_service_cache:
        _action_service_cache[action_lower] = get_valid_resource_services_for_action(action)

    valid_services, wildcard_only, found_in_policy_sentry = _action_service_cache[action_lower]

    # If action only supports wildcard, reject specific ARNs
    if wildcard_only:
        return False

    # If policy_sentry knows about this action and found specific services
    if found_in_policy_sentry and valid_services:
        return resource_service in valid_services

    # Fallback: if policy_sentry doesn't know the action, use simple service matching
    # Check for known cross-service mappings first
    action_service = get_service_from_action(action)
    if action_service:
        # Check cross-service mappings
        if action_service in CROSS_SERVICE_RESOURCE_MAPPINGS:
            allowed_resource_services = CROSS_SERVICE_RESOURCE_MAPPINGS[action_service]
            return resource_service in allowed_resource_services or resource_service == action_service
        
        # Simple service prefix match as fallback
        return resource_service == action_service

    return True


def filter_resources_for_action(action, resources):
    """
    Filter resources to only those that are valid for the given action.
    Args: action (str): IAM action like "s3:GetObject"
    Args: resources (set): Set of resource ARNs
    returns: set: Filtered set of valid resources
    """
    return {r for r in resources if is_resource_valid_for_action(action, r)}


def enumerate_actions_resources_for_statements(list_of_statements):
    """
    Enumerates resources and expanded actions for a list of statements
    Args: list_of_statements (list): list of statement JSON objects from a policy
    returns: dict: a dictionary of actions with the following structure:

    {
        "someAction": {
            "Deny_resources": [],
            "Deny_conditions": [],
            "Allow_resources": [],
            "Allow_conditions": []
        },
        "someOtherAction": {
            "Deny_resources": [],
            "Deny_conditions": [],
            "Allow_resources": [],
            "Allow_conditions": []
        }
    }
    """
    results = {}

    def new_action_dict():
        # returns a new action dictionary
        return {
            "Deny_resources": set(),
            "Deny_conditions": [],
            "Allow_resources": set(),
            "Allow_conditions": [],
        }

    for st in list_of_statements:
        try:
            statement = ExtendedStatement(st)
        except Exception as e:
            print(e)
            print("[!] Error parsing statement")
            continue

        # iterate through the found query actions
        for action in statement.actions_expanded:
            effect_key = statement.effect

            # Set the action dictionary to the results dictionary if it exists
            # otherwise create a new action dictionary
            action_dict = results.get(action, new_action_dict())

            # Add resources to the Deny_resources set if there is a notresources and effect is Allow
            if statement.notresources and statement.effect == "Allow":
                filtered_notresources = filter_resources_for_action(action, statement.notresources)
                updated_resources = action_dict["Deny_resources"].union(filtered_notresources)
                action_dict.update({"Deny_resources": updated_resources})

            if statement.notresources and statement.effect == "Deny":
                # Add a condition in this case since it means access is denied
                # but does not mean any other access is allowed
                # TODO maybe a better way to do this but for now here we are.
                filtered_notresources = filter_resources_for_action(action, statement.notresources)
                if filtered_notresources:
                    action_dict["Allow_conditions"].append({"StringEquals": {"aws:ResourceArn": filtered_notresources}})

            # Update the Allow or Deny resources (filtered to valid resources for this action)
            filtered_resources = filter_resources_for_action(action, statement.resources)
            updated_resources = action_dict[f"{effect_key}_resources"].union(filtered_resources)
            action_dict.update({f"{effect_key}_resources": updated_resources})

            # Add conditions if any exist
            if statement.conditions:
                action_dict[f"{effect_key}_conditions"].append(statement.conditions)

            # Update the results for the actions
            results[action] = action_dict

    # Filter out actions with no resources or conditions
    results = {
        action: data for action, data in results.items()
        if data["Deny_resources"] or data["Deny_conditions"] or
           data["Allow_resources"] or data["Allow_conditions"]
    }

    return convert_sets_to_lists(results)