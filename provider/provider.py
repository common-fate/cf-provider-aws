import typing
from commonfate_provider import provider, args, diagnostics, resources, tasks
import boto3

from treelib import Tree
import re

class OrgUnit(resources.Resource):
    parent: typing.Optional[str] = resources.Related("OrgUnit")
    name: typing.Optional[str] = resources.Name()


class Account(resources.Resource):
    tags: dict = {}
    name: typing.Optional[str] = resources.Name()
    org_unit: str = resources.Related(OrgUnit)


class PermissionSet(resources.Resource):
    name: typing.Optional[str] = resources.Name()


class ManagedPolicy(resources.Resource):
    name: typing.Optional[str] = resources.Name()


class ManagedPolicyAttachment(resources.Resource):
    permission_set: str = resources.Related(PermissionSet)
    managed_policy: str = resources.Related(ManagedPolicy)


class Group(resources.Resource):
    name: typing.Optional[str] = resources.Name()
    description: typing.Optional[str] = None


class User(resources.Resource):
    email: str = resources.UserEmail()
    name: typing.Optional[str] = resources.Name()


class GroupMembership(resources.Resource):
    user: str = resources.Related(User)
    group: str = resources.Related(Group)


class AccountAssignment(resources.Resource):
    permission_set: str = resources.Related(PermissionSet)
    account: str = resources.Related(Account)
    user: typing.Optional[str] = resources.Related(User)
    group: typing.Optional[str] = resources.Related(Group)

class Provider(provider.Provider):
    instance_arn = provider.String(usage="the AWS SSO instance ARN")
    identity_store_id = provider.String(usage="the AWS SSO identity store ID")
    region = provider.String(usage="the AWS SSO instance region")

    def __init__(self, config_loader):
        super().__init__(config_loader)
        self.org_client = boto3.client("organizations", region_name=self.region.get())
        self.sso_client = boto3.client("sso-admin", region_name=self.region.get())
        self.idstore_client = boto3.client(
            "identitystore", region_name=self.region.get()
        )


def all_accounts(tree: Tree, org_unit_id: str) -> typing.List[str]:
    """
    look through the children of the tree node recursively to find all accounts
    belong to the OU with ID `org_unit_id`
    """
    accounts: typing.List[str] = []
    childs = tree.children(org_unit_id)
    for child in childs:
        if isinstance(child.data, Account):
            accounts.append(child.data.id)
        if isinstance(child.data, OrgUnit):
            child_accounts = all_accounts(tree, child.data.id)
            accounts = accounts + child_accounts

    return accounts


class OrgUnitGroup(args.Group):
    title = "Org Unit"
    description = "The AWS Organizational Unit"
    resource = OrgUnit

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # build a tree containing the accounts and org units

        accounts = resources.query(Account).all()
        ous = resources.query(OrgUnit).all()
        self.tree = Tree()
        for ou in ous:
            self.tree.create_node(identifier=ou.id, parent=ou.parent, data=ou)

        for account in accounts:
            self.tree.create_node(
                identifier=account.id, parent=account.org_unit, data=account
            )

    def match(self, key):
        matching_accounts = all_accounts(self.tree, key)
        return matching_accounts


class TagGroup(args.Group):
    title = "Tag"
    description = "The AWS account tag"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.accounts = resources.query(Account).all()

    def match(self, key):
        matching_accounts: typing.List[str] = []
        # split 'mytag=myvalue' into ['mytag', 'myvalue']
        [tag, pattern] = key.split("=", 1)
        for account in self.accounts:
            value = account.tags.get(tag)
            if value is not None and re.match(pattern, value):
                matching_accounts.append(account.id)

        return matching_accounts


class Args(args.Args):
    account = args.Resource(
        title="Account",
        resource=Account,
        description="the AWS account to grant access to",
        groups=(OrgUnitGroup, TagGroup),
        rule_element=args.FormElement.MULTISELECT,
        request_element=args.FormElement.SELECT
    )
    permission_set = args.Resource(
        title="Permission Set",
        resource=PermissionSet,
        description="the AWS permission set to grant access to",
        rule_element=args.FormElement.MULTISELECT,
        request_element=args.FormElement.SELECT,
    )
  

@provider.grant()
def grant(p: Provider, subject, args: Args) -> provider.GrantResult:
    print(
        f"granting access to {subject}, group={args.account}, url={p.instance_arn.get()}"
    )

    return provider.GrantResult(
        access_instructions="this is how to access the permissions"
    )


@provider.revoke()
def revoke(p: Provider, subject, args: Args):
    print(
        f"revoking access from {subject}, group={args.account}, url={p.instance_arn.get()}"
    )


@provider.config_validator(name="List Users")
def can_list_users(p: Provider, diagnostics: diagnostics.Logs) -> None:
    diagnostics.info("some message here")


@provider.grant_validator(name="User Exists")
def user_exists(p: Provider, subject: str, args: Args):
    pass


@provider.grant_validator(name="Account Exists")
def account_exists(p: Provider, subject: str, args: Args):
    account = resources.query(Account).all()

def next_token(page: typing.Optional[str]) -> dict:
    """
    returns a type-safe next token for use with boto3
    """
    if page is None:
        return {}  # type: ignore
    return {"NextToken": page}


class OrgUnitContext(resources.Context):
    parent_id: str
    page: typing.Optional[str] = None


class ListChildrenForOU(tasks.Task):
    parent_id: str
    """the parent to list children for"""
    page: typing.Optional[str] = None
    """handles AWS pagination"""

    def run(self, p: Provider):
        res = p.org_client.list_children(
            ParentId=self.parent_id,
            ChildType="ORGANIZATIONAL_UNIT",
            **next_token(self.page),
        )
        for ou in res["Children"]:
            id = ou.get("Id")
            if id is not None:
                tasks.call(DescribeOU(id=id, parent_id=self.parent_id))
                # recursively list children for the child OU to traverse the full org tree.
                tasks.call(ListChildrenForOU(parent_id=id))
                tasks.call(ListAccountsForOU(parent_id=id))
        if res.get("NextToken") is not None:
            # iterate through pages
            self.page = res["NextToken"]
            tasks.call(self)


class DescribeOU(tasks.Task):
    id: str
    parent_id: str

    def run(self, p: Provider):
        res = p.org_client.describe_organizational_unit(OrganizationalUnitId=self.id)
        ou = res["OrganizationalUnit"]
        resources.register(
            OrgUnit(
                id=self.id,
                name=ou.get("Name"),
                parent=self.parent_id,
            )
        )


class ListAccountsForOU(tasks.Task):
    parent_id: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.org_client.list_children(
            ParentId=self.parent_id, ChildType="ACCOUNT", **next_token(self.page)
        )
        for account in res["Children"]:
            id = account.get("Id")
            if id is not None:
                tasks.call(
                    DescribeAccount(account_id=id, org_unit=self.parent_id),
                )
        if res.get("NextToken") is not None:
            # iterate through pages
            self.page = res["NextToken"]
            tasks.call(self)


class DescribeAccount(tasks.Task):
    account_id: str
    org_unit: str

    def run(self, p):
        res = p.org_client.describe_account(AccountId=self.account_id)
        name = res["Account"].get("Name")
        acc = Account(
            org_unit=self.org_unit,
            id=self.account_id,
            name=name,
        )

        # find the tags associated with the account
        paginator = p.org_client.get_paginator("list_tags_for_resource")
        page_iterator = paginator.paginate(ResourceId=self.account_id)
        for page in page_iterator:
            tags = page["Tags"]
            for t in tags:
                acc.tags[t["Key"]] = t["Value"]

        resources.register(acc)


@resources.fetcher
def fetch_org_structure(p: Provider):
    list_roots = p.org_client.list_roots()
    root = list_roots["Roots"][0]
    root_id = root.get("Id")
    if root_id is None:
        raise Exception("could not find org root")
    resources.register(OrgUnit(id=root_id))
    tasks.call(ListChildrenForOU(parent_id=root_id))
    tasks.call(ListAccountsForOU(parent_id=root_id))


class ListPermissionSets(tasks.Task):
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.sso_client.list_permission_sets(
            InstanceArn=p.instance_arn.get(), **next_token(self.page)
        )
        for ps in res["PermissionSets"]:
            tasks.call(
                DescribePermissionSet(permission_set_arn=ps),
            )
            tasks.call(ListManagedPoliciesInPermissionSet(permission_set_arn=ps))
            tasks.call(ListAccountAssignments(permission_set_arn=ps))

        if res.get("NextToken") is not None:
            self.page = res["NextToken"]
            tasks.call(self)


class DescribePermissionSet(tasks.Task):
    permission_set_arn: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.sso_client.describe_permission_set(
            InstanceArn=p.instance_arn.get(), PermissionSetArn=self.permission_set_arn
        )
        ps = res["PermissionSet"]

        resources.register(
            PermissionSet(
                id=self.permission_set_arn,
                name=ps.get("Name"),
            )
        )


class ListManagedPoliciesInPermissionSet(tasks.Task):
    permission_set_arn: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.sso_client.list_managed_policies_in_permission_set(
            InstanceArn=p.instance_arn.get(),
            PermissionSetArn=self.permission_set_arn,
            **next_token(self.page),
        )
        for mp in res["AttachedManagedPolicies"]:
            arn = mp.get("Arn")
            if arn is not None:
                resources.register(ManagedPolicy(id=arn, name=mp.get("Name")))

                # generate a composite ID for the ManagedPolicyAttachment object
                mpa_id = self.permission_set_arn + "/" + arn
                resources.register(
                    ManagedPolicyAttachment(
                        id=mpa_id,
                        managed_policy=arn,
                        permission_set=self.permission_set_arn,
                    )
                )

        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


class ListAccountAssignments(tasks.Task):
    permission_set_arn: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.sso_client.list_accounts_for_provisioned_permission_set(
            InstanceArn=p.instance_arn.get(),
            PermissionSetArn=self.permission_set_arn,
            **next_token(self.page),
        )
        for account in res["AccountIds"]:
            tasks.call(
                DescribeAccountAssignment(
                    permission_set_arn=self.permission_set_arn, account_id=account
                ),
            )
        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


class DescribeAccountAssignment(tasks.Task):
    account_id: str
    permission_set_arn: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.sso_client.list_account_assignments(
            InstanceArn=p.instance_arn.get(),
            AccountId=self.account_id,
            PermissionSetArn=self.permission_set_arn,
            **next_token(self.page),
        )
        for aa in res["AccountAssignments"]:
            principal_id = aa.get("PrincipalId")
            if principal_id is not None:
                a = AccountAssignment(
                    id=resources.composite_id(
                        [self.account_id, self.permission_set_arn, principal_id]
                    ),
                    account=self.account_id,
                    permission_set=self.permission_set_arn,
                )
                if aa.get("PrincipalType") == "USER":
                    a.user = principal_id
                else:
                    a.group = principal_id
                resources.register(a)

        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


@resources.fetcher
def fetch_permission_sets(p: Provider):
    tasks.call(ListPermissionSets())


class ListUsers(tasks.Task):
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.idstore_client.list_users(
            IdentityStoreId=p.identity_store_id.get(), **next_token(self.page)
        )
        for u in res["Users"]:
            primary_email = next(
                (
                    e.get("Value")
                    for e in u.get("Emails", [])
                    if e.get("Primary") is True
                ),
                None,
            )
            if primary_email is not None:
                resources.register(User(id=u["UserId"], email=primary_email))

        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


class ListGroups(tasks.Task):
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.idstore_client.list_groups(
            IdentityStoreId=p.identity_store_id.get(), **next_token(self.page)
        )
        for g in res["Groups"]:
            id = g["GroupId"]
            resources.register(
                Group(
                    id=id, description=g.get("Description"), name=g.get("DisplayName")
                )
            )
            tasks.call(ListGroupMemberships(group_id=id))

        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


class ListGroupMemberships(tasks.Task):
    group_id: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.idstore_client.list_group_memberships(
            IdentityStoreId=p.identity_store_id.get(),
            GroupId=self.group_id,
            **next_token(self.page),
        )
        for g in res["GroupMemberships"]:
            id = g.get("MembershipId")
            user_id = g.get("MemberId", {}).get("UserId", "")
            if id is not None:
                resources.register(
                    GroupMembership(id=id, user=user_id, group=self.group_id)
                )

        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


@resources.fetcher
def fetch_users(p: Provider):
    tasks.call(ListUsers())


@resources.fetcher
def fetch_groups(p: Provider):
    tasks.call(ListGroups())
