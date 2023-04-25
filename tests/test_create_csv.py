import os

from lib.create_csv import process_json_and_append_to_csv


def test_process_json_and_append_to_csv():
    json_data = {
        "someAction": {
            "Deny_resources": ["a/denied/resource", "another/denied/resource"],
            "Deny_conditions": ["someCondition", "anotherCondition"],
            "Allow_resources": ["a/allowed/resource", "another/allowed/resource"],
            "Allow_conditions": ["someCondition", "anotherCondition"],
        },
        "someOtherAction": {
            "Deny_resources": ["a/denied/resource", "another/denied/resource"],
            "Deny_conditions": ["someCondition", "anotherCondition"],
            "Allow_resources": ["a/allowed/resource", "another/allowed/resource"],
            "Allow_conditions": ["someCondition", "anotherCondition"],
        },
    }
    csv_file = "tmp-test.csv"
    process_json_and_append_to_csv(json_data, csv_file, "somePrincipalID")
    with open(csv_file, "r") as f:
        csv_contents = f.read()

        try:
            # I do not know why but pandas to_csv does not always write in the same order
            # It returns 1 of 2 orders so check against either, order is not important here
            assert (
                csv_contents == "Principal,Allowed Action,Denied"
                " Action,Resource,Conditions\nsomePrincipalID,someAction,,a/allowed/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,someAction,,another/allowed/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,,someAction,a/denied/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,,someAction,another/denied/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,someOtherAction,,a/allowed/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,someOtherAction,,another/allowed/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,,someOtherAction,a/denied/resource,\"['someCondition',"
                " 'anotherCondition']\"\nsomePrincipalID,,someOtherAction,another/denied/resource,\"['someCondition',"
                " 'anotherCondition']\"\n"
                or "Principal,Allowed Action,Denied Action,Resource,Conditions\nsomePrincipalID,someAction,,a/allowed/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,someAction,,another/allowed/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,,someAction,another/denied/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,,someAction,a/denied/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,someOtherAction,,a/allowed/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,someOtherAction,,another/allowed/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,,someOtherAction,another/denied/resource,\"['someCondition', 'anotherCondition']\"\nsomePrincipalID,,someOtherAction,a/denied/resource,\"['someCondition', 'anotherCondition']\"\n"  # noqa
            )
        finally:
            os.remove(csv_file)
