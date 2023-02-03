import typing
from commonfate_provider import provider, args, diagnostics, resources
import boto3
from provider.resources import Account, OrgUnit, PermissionSet, AccountAssignment
from treelib import Tree
import re


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
