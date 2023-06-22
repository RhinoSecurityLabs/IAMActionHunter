from policyuniverse.statement import Statement


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

    # actions_to_check = []
    for st in list_of_statements:
        try:
            statement = ExtendedStatement(st)
        except Exception as e:
            print(e)
            print("[!] Error parsing statement")
            continue

        # Expand the actions to check using policyuniverse
        # actions_to_check = query_actions  # Statement({"Action": query_actions}).actions_expanded

        # Get all the query actions which are in the statement
        # found_actions = [action for action in actions_to_check if action in statement.actions_expanded]

        # iterate through the found query actions
        for action in statement.actions_expanded:
            effect_key = statement.effect

            # Set the action dictionary to the results dictionary if it exists
            # otherwise create a new action dictionary
            action_dict = results.get(action, new_action_dict())

            # Add resources to the Deny_resources set if there is a notresources and effect is Allow
            if statement.notresources and statement.effect == "Allow":
                updated_resources = action_dict["Deny_resources"].union(statement.notresources)
                action_dict.update({"Deny_resources": updated_resources})

            if statement.notresources and statement.effect == "Deny":
                # Add a condition in this case since it means access is denied
                # but does not mean any other access is allowed
                # TODO maybe a better way to do this but for now here we are.
                action_dict["Deny_conditions"].append({"IfResourcesNotIn": statement.notresources})

            if statement.notresources and statement.effect == "Allow":
                # Add a condition in this case since it means access is allowed
                # to everything except the notresources
                # TODO maybe a better way to do this but for now here we are.
                action_dict["Allow_conditions"].append({"IfResourcesNotIn": statement.notresources})

            # Update the Allow or Deny resources
            updated_resources = action_dict[f"{effect_key}_resources"].union(statement.resources)
            action_dict.update({f"{effect_key}_resources": updated_resources})

            # Add conditions if any exist
            if statement.conditions:
                action_dict[f"{effect_key}_conditions"].append(statement.conditions)

            # Update the results for the actions
            results[action] = action_dict

    # if all_or_none_actions and not all(
    #     results.get(action, {"Allow_resources": {}})["Allow_resources"]
    #     for action in actions_to_check
    # ):
    #     # If all_or_none_actions is True, check if all the query actions are in the results
    #     # If not, return an empty dictionary
    #     results = {}

    return convert_sets_to_lists(results)
