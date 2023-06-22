dangerous_iam = [
    {
        "Description": "This is a list of IAM actions that can be used to escalate privileges or move laterally.",
        "Name": "DangerousIAMActions",
        "ActionsNeeded": [
            "iam:PutGroupPolicy",
            "iam:PutRolePolicy",
            "iam:PutUserPolicy",
            "iam:AttachGroupPolicy",
            "iam:AttachRolePolicy",
            "iam:AttachUserPolicy",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
            "iam:AddUserToGroup",
            "iam:CreateLoginProfile",
            "iam:UpdateLoginProfile",
            "iam:CreateAccessKey",
            "iam:CreateRole",
            "sts:assumerole",
        ],
        "AllOrNone": False,
    }
]

write_actions = [
    {
        "Description": "These are all actions which may allow some kind of write privilege.",
        "Name": "WriteActions",
        "ActionsNeeded": [
            "*:Put*",
            "*:Create*",
            "*:Delete*",
            "*:Modify*",
            "*:Update*",
            "*:Attach*",
            "*:Detach*",
            "*:Associate*",
            "*:Disassociate*",
            "*:Add*",
            "*:Remove*",
            "*:Set*",
            "*:Enable*",
            "*:Disable*",
            "*:Reset*",
            "*:Stop*",
            "*:Terminate*",
            "*:Reboot*",
            "*:Start*",
        ],
        "AllOrNone": False,
    }
]


privescs = [
    {
        "Description": "",
        "Name": "CreateNewPolicyVersion",
        "ActionsNeeded": [
            "iam:CreatePolicyVersion",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "SetExistingDefaultPolicyVersion",
        "ActionsNeeded": [
            "iam:SetDefaultPolicyVersion",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "CreateEC2WithExistingIP",
        "ActionsNeeded": [
            "iam:PassRole",
            "ec2:RunInstances",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "CreateAccessKey",
        "ActionsNeeded": [
            "iam:CreateAccessKey",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "CreateLoginProfile",
        "ActionsNeeded": [
            "iam:CreateLoginProfile",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "UpdateLoginProfile",
        "ActionsNeeded": [
            "iam:UpdateLoginProfile",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "AttachRolePolicy",
        "ActionsNeeded": [
            "iam:AttachRolePolicy",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PutRolePolicy",
        "ActionsNeeded": [
            "iam:PutRolePolicy",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "UpdateRolePolicyToAssumeIt",
        "ActionsNeeded": [
            "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewLambdaThenInvoke",
        "ActionsNeeded": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewLambdaThenInvokeCrossAccount",
        "ActionsNeeded": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:AddPermission",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo",
        "ActionsNeeded": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping",
            "dynamodb:CreateTable",
            "dynamodb:PutItem",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo",
        "ActionsNeeded": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewGlueDevEndpoint",
        "ActionsNeeded": [
            "iam:PassRole",
            "glue:CreateDevEndpoint",
            "glue:GetDevEndpoint",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "UpdateExistingGlueDevEndpoint",
        "ActionsNeeded": [
            "glue:UpdateDevEndpoint",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewCloudFormation",
        "ActionsNeeded": [
            "iam:PassRole",
            "cloudformation:CreateStack",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewDataPipeline",
        "ActionsNeeded": [
            "iam:PassRole",
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "EditExistingLambdaFunctionWithRole",
        "ActionsNeeded": [
            "lambda:UpdateFunctionCode",
        ],
        "AllOrNone": True,
    },
    {
        "Description": "",
        "Name": "PassExistingRoleToNewCodeStarProject",
        "ActionsNeeded": [
            "codestar:CreateProject",
            "iam:PassRole",
        ],
        "AllOrNone": True,
    },
]
