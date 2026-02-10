# IAMActionHunter

IAMActionHunter is an IAM policy statement parser and query tool that simplifies collecting and understanding permission policies for users and roles in AWS Identity and Access Management (IAM). It also provides privilege escalation analysis and **Neo4j graph visualization** of attack paths, similar to BloodHound but for AWS IAM.

### Blog Post

https://rhinosecuritylabs.com/aws/iamactionhunter-aws-iam-permissions/

## Features

- **Collect** IAM policies for all users and roles in an AWS account
- **Query** permissions with wildcard support
- **Analyze** privilege escalation paths via AssumeRole chains
- **Visualize** attack paths in Neo4j with BloodHound-style graphs
- **Filter** results by specific users or roles
- **Export** results to CSV

## Offensive Use

Search for potential privilege escalation opportunities by querying AWS IAM actions that might be exploited. The graph visualization shows progression paths from a compromised principal to higher privileges.

## Blue Team Use

Generate CSV reports of principal permissions and resources. Use the graph feature to understand the blast radius of a compromised credential.

# Installation

```bash
pip3 install iamactionhunter
```

Or clone and install with Poetry:

```bash
git clone https://github.com/RhinoSecurityLabs/IAMActionHunter.git
cd IAMActionHunter
poetry install
```

For graph visualization, also install the Neo4j driver:

```bash
pip install neo4j
# or
poetry add neo4j
```

# Usage

IAMActionHunter uses subcommands for different operations:

```
usage: iah [-h] {list,collect,query,privesc,graph} ...

IAMActionHunter - AWS IAM policy analysis and privilege escalation detection

positional arguments:
  {list,collect,query,privesc,graph}
                        Available commands
    list                List available accounts
    collect             Collect and analyze IAM policies from AWS
    query               Query permissions for users/roles
    privesc             Analyze privilege escalation paths via AssumeRole
    graph               Generate Neo4j graph for visualization

optional arguments:
  -h, --help            show this help message and exit
```

## Collect

Download IAM data for an AWS account:

```bash
iah collect --profile my-aws-profile
```

Re-analyze existing data without making API calls:

```bash
iah collect --account 123456789012
```

## List

List accounts that have been collected:

```bash
iah list
```

## Query

Query permissions across users and roles:

```bash
# Basic query
iah query --account 123456789012 --query iam:create*

# Multiple actions
iah query --account 123456789012 --query iam:create*,iam:put*

# Filter by role
iah query --account 123456789012 --role AdminRole --query iam:*

# Filter by user
iah query --account 123456789012 --user alice --query s3:*

# Only show results if ALL queried actions are allowed
iah query --account 123456789012 --query s3:GetObject,s3:PutObject --all-or-none

# Export to CSV
iah query --account 123456789012 --query iam:* --csv report.csv

# Use a preset config
iah query --account 123456789012 --config dangerous_iam

# Exclude permissions that another principal also has
iah query --account 123456789012 --query iam:* --filter-principal BaselineRole
```

## Privesc

Analyze privilege escalation paths:

```bash
iah privesc --account 123456789012

# Filter to specific roles
iah privesc --account 123456789012 --role DevRole,TestRole

# Filter to specific users  
iah privesc --account 123456789012 --user alice,bob
```

## Graph

Generate a Neo4j graph for BloodHound-style visualization of privilege escalation paths.

### Prerequisites

Start a Neo4j container:

```bash
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password neo4j
```

### Basic Usage

Generate a full graph of all relationships:

```bash
iah graph --account 123456789012 --neo4j-password password --clear
```

### BFS Traversal from Starting Point

Generate a graph showing only progression paths from a specific principal. This uses BFS traversal and only draws the first edge to reach each node (showing how an attacker would progress, not all possible relationships):

```bash
# Start from a specific role
iah graph --account 123456789012 --neo4j-password password --clear \
  --start MyCompromisedRole

# Control traversal depth (default: 5)
iah graph --account 123456789012 --neo4j-password password --clear \
  --start MyCompromisedRole --depth 10
```

### Filtering

```bash
# Only include specific roles
iah graph --account 123456789012 --neo4j-password password --clear \
  --role AdminRole,DevRole,TestRole

# Only include specific users
iah graph --account 123456789012 --neo4j-password password --clear \
  --user alice,bob

# Include AWS service-linked roles (excluded by default)
iah graph --account 123456789012 --neo4j-password password --clear \
  --include-service-roles
```

### Graph Options

```
--account           Account ID to graph (required)
--neo4j-uri         Neo4j connection URI (default: bolt://localhost:7687)
--neo4j-user        Neo4j username (default: neo4j)
--neo4j-password    Neo4j password (default: neo4j)
--clear             Clear existing graph data before import
--include-service-roles  Include AWS service-linked roles
--role              Filter by role (comma-separated or file path)
--user              Filter by user (comma-separated or file path)
--start             Starting principal for BFS traversal
--depth             Max traversal depth when using --start (default: 5)
```

### Neo4j Cypher Queries

Open Neo4j Browser at http://localhost:7474 and try these queries:

```cypher
-- View the entire graph
MATCH p=()-[]->() RETURN p

-- Limit results
MATCH p=()-[]->() RETURN p LIMIT 100

-- All paths from a specific role
MATCH p=(r:Role {name: 'MyRole'})-[*1..5]->() RETURN p

-- Paths with 2+ hops (chains)
MATCH p=(r:Role {name: 'MyRole'})-[*2..]->() RETURN p

-- Paths with exactly 2 hops
MATCH p=(r:Role {name: 'MyRole'})-[*2]->() RETURN p

-- Specific privesc method
MATCH p=(r:Role {name: 'MyRole'})-[:CreateEC2WithExistingIP]->(dest) RETURN p

-- Any privesc (single hop, exclude AssumeRole)
MATCH p=(r:Role {name: 'MyRole'})-[pe]->(dest)
WHERE type(pe) <> 'AssumeRole'
RETURN p

-- Exclude conditional edges (more reliable paths)
MATCH p=(a)-[r]->(b)
WHERE NOT type(r) ENDS WITH '-conditional'
RETURN p LIMIT 50

-- Exclude wildcard targets (ANY_USER, ANY_ROLE)
MATCH p=(a)-[r]->(b)
WHERE NOT b.arn = '*'
RETURN p LIMIT 50

-- Find all paths to a high-value role
MATCH p=()-[*1..4]->(r:Role {name: 'AdminRole'}) RETURN p

-- Node counts by type
MATCH (n) RETURN labels(n), count(*)

-- Edge counts by type
MATCH ()-[r]->() RETURN type(r), count(*)
```

### Graph Data Model

**Nodes:**
- `User` - IAM users
- `Role` - IAM roles  
- `Group` - IAM groups
- `Resource` - AWS resources (policies, Lambda functions, etc.)
- `ANY_USER` - Wildcard node representing any user
- `ANY_ROLE` - Wildcard node representing any role

**Edges:**
- `AssumeRole` - Principal can assume the target role
- `AssumeRole-conditional` - AssumeRole with conditions in trust policy
- `MemberOf` - User is member of group
- `CreateAccessKey` - Can create access key for target user
- `CreateLoginProfile` - Can create console login for target user
- `CreateEC2WithExistingIP` - Can launch EC2 with target role's instance profile
- `PassExistingRoleToNewLambdaThenInvoke` - Can pass role to Lambda and invoke
- `AttachRolePolicy` - Can attach policies to target role
- `PutRolePolicy` - Can put inline policy on target role
- ... and other privilege escalation methods

Edges ending in `-conditional` indicate the trust policy has conditions that must be met.

## Configs

Built-in config options:

```
dangerous_iam
write_actions
privescs
```

```bash
iah query --account 123456789012 --config dangerous_iam
```

### Custom Configs

Create a JSON file specifying permissions to search for:

```json
[
  {
    "Description": "CodeBuild write actions",
    "Name": "CodeBuildWriteActions",
    "ActionsNeeded": [
      "codebuild:Create*",
      "codebuild:Update*",
      "codebuild:Delete*",
      "codebuild:Start*"
    ],
    "AllOrNone": false
  }
]
```

Run with:

```bash
iah query --account 123456789012 --config my_config.json
```

## Data Storage

Collected data is stored in `~/.iamactionhunter/<account_id>/`:

```
~/.iamactionhunter/
└── 123456789012/
    ├── raw/
    │   ├── principals/
    │   │   ├── users/
    │   │   └── roles/
    │   └── policies/
    │       └── trust/
    ├── users/
    │   └── <user>.json
    └── roles/
        └── <role>.json
```

## License

Apache-2.0

## Credits

Developed by [Rhino Security Labs](https://rhinosecuritylabs.com)

Graph visualization inspired by [BloodHound](https://github.com/BloodHoundAD/BloodHound)