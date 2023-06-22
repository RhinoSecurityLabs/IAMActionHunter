import pandas as pd
import os


def process_json_and_append_to_csv(json_data, csv_file, principal):
    """
    Process the JSON data and append it to the CSV file
    Args: json_data (string): JSON data to process
    Args: csv_file (string): CSV file to append to
    returns: None
    """

    # Load JSON data into a Python dictionary
    # data = json.loads(json_data)

    # Create an empty DataFrame with the required columns
    df = pd.DataFrame(
        columns=[
            "Principal",
            "Allowed Action",
            "Denied Action",
            "Resource",
            "Conditions",
        ]
    )

    # Create a list to store DataFrame rows
    rows = []

    # Populate the DataFrame with the JSON data
    for action in json_data:
        for allowed_resource in json_data[action]["Allow_resources"]:
            rows.append(
                {
                    "Principal": principal,
                    "Allowed Action": action,
                    "Denied Action": "",
                    "Resource": allowed_resource,
                    "Conditions": json_data[action]["Allow_conditions"],
                }
            )

        for denied_resource in json_data[action]["Deny_resources"]:
            rows.append(
                {
                    "Principal": principal,
                    "Allowed Action": "",
                    "Denied Action": action,
                    "Resource": denied_resource,
                    "Conditions": json_data[action]["Deny_conditions"],
                }
            )

    # Concatenate the rows to the DataFrame
    df = pd.concat([df, pd.DataFrame(rows)], ignore_index=True)

    # Check if the CSV file exists, and write the header if necessary
    if not os.path.isfile(csv_file):
        df.to_csv(csv_file, index=False, mode="w", header=True)
    else:
        df.to_csv(csv_file, index=False, mode="a", header=False)
