from dataclasses import dataclass
import typing
import provider
from provider import target, access, diagnostics, resources, tasks
import boto3
import botocore.session
from botocore.credentials import (
    AssumeRoleCredentialFetcher,
    DeferredRefreshableCredentials,
)
from retrying import retry
import structlog

log = structlog.get_logger()


class OrgUnit(resources.Resource):
    parent: typing.Optional[str] = resources.Related("OrgUnit")


@dataclass
class SSOUser:
    UserId: str
    UserName: str


class Account(resources.Resource):
    tags: dict = {}
    name: str
    parent_org_unit: str = resources.Related(
        OrgUnit,
        title="AWS Organizational Unit",
        description="A parent organizational unit for the account",
    )
    # root/ou-1/ou2/
    org_unit_path: str


class PermissionSet(resources.Resource):
    pass


class ManagedPolicy(resources.Resource):
    pass


class ManagedPolicyAttachment(resources.BaseResource):
    permission_set: str = resources.Related(PermissionSet)
    managed_policy: str = resources.Related(ManagedPolicy)


class Group(resources.Resource):
    description: typing.Optional[str] = None


class User(resources.Resource):
    email: str


class GroupMembership(resources.BaseResource):
    user: str = resources.Related(User)
    group: str = resources.Related(Group)


class AccountAssignment(resources.BaseResource):
    permission_set: str = resources.Related(PermissionSet)
    account: str = resources.Related(Account)
    user: typing.Optional[str] = resources.Related(User)
    group: typing.Optional[str] = resources.Related(Group)


class Provider(provider.Provider):
    sso_instance_arn = provider.String(description="the AWS SSO instance ARN")
    sso_identity_store_id = provider.String(description="the AWS SSO identity store ID")
    sso_region = provider.String(description="the AWS SSO instance region")
    sso_role_arn = provider.String(
        description="The ARN of the AWS IAM Role with permission to administer SSO"
    )

    def setup(self):
        self.org_client = get_boto3_session(role_arn=self.sso_role_arn.get()).client(
            "organizations", region_name=self.sso_region.get()
        )
        self.sso_client = get_boto3_session(role_arn=self.sso_role_arn.get()).client(
            "sso-admin", region_name=self.sso_region.get()
        )
        self.idstore_client = get_boto3_session(
            role_arn=self.sso_role_arn.get()
        ).client("identitystore", region_name=self.sso_region.get())

    def get_user(self, subject) -> SSOUser:
        # try get user first by filtering username
        out = self.idstore_client.list_users(
            IdentityStoreId=self.sso_identity_store_id.get(),
            MaxResults=1,
            Filters=[{"AttributePath": "UserName", "AttributeValue": subject}],
        )

        if len(out["Users"]) != 0:
            return SSOUser(
                UserId=out["Users"][0]["UserId"], UserName=out["Users"][0]["UserName"]
            )

        # if we didnt find the user via the username
        # list all users and find a match in the subject email

        has_more = True
        next_token = ""

        while has_more:
            users = self.idstore_client.list_users(
                IdentityStoreId=self.sso_identity_store_id.get(),
                NextToken=next_token,
            )

            for user in users["Users"]:
                for email in user["Emails"]:
                    if email["Value"] == subject:
                        return SSOUser(UserId=user["UserId"], UserName=user["UserName"])

            next_token = users["NextToken"]
            has_more = next_token != ""

        raise Exception(f"user {subject} does not exist in AWS SSO directory")


@access.target(kind="Account")
class AccountTarget:
    account = target.Resource(
        title="Account",
        resource=Account,
        description="the AWS account to grant access to",
    )
    permission_set = target.Resource(
        title="Permission Set",
        resource=PermissionSet,
        description="the AWS permission set to grant access to",
    )


class NotReadyError(Exception):
    pass


def retry_on_notready(exc):
    return isinstance(exc, NotReadyError)


# retry for 2 minutes
@retry(stop_max_delay=60000 * 2, retry_on_exception=retry_on_notready)
def check_account_assignment_status(p: Provider, request_id):
    acc_assignment = p.sso_client.describe_account_assignment_creation_status(
        InstanceArn=p.sso_instance_arn.get(),
        AccountAssignmentCreationRequestId=request_id,
    )

    if acc_assignment["AccountAssignmentCreationStatus"]["Status"] == "SUCCEEDED":
        return acc_assignment
    else:
        if acc_assignment["AccountAssignmentCreationStatus"]["Status"] == "FAILED":
            return acc_assignment

        # trigger a retry
        raise NotReadyError


@retry(stop_max_delay=60000 * 2, retry_on_exception=retry_on_notready)
def check_account_deletion_status(p: Provider, request_id):
    acc_assignment = p.sso_client.describe_account_assignment_deletion_status(
        InstanceArn=p.sso_instance_arn.get(),
        AccountAssignmentDeletionRequestId=request_id,
    )

    if acc_assignment["AccountAssignmentDeletionStatus"]["Status"] == "SUCCEEDED":
        return acc_assignment
    else:
        if acc_assignment["AccountAssignmentDeletionStatus"]["Status"] == "FAILED":
            return acc_assignment

        # trigger a retry
        raise NotReadyError


@access.grant()
def grant(p: Provider, subject: str, target: AccountTarget) -> access.GrantResult:
    # find the user id from the email address subject
    user = p.get_user(subject)

    acc_assignment = p.sso_client.create_account_assignment(
        InstanceArn=p.sso_instance_arn.get(),
        PermissionSetArn=target.permission_set,
        PrincipalType="USER",
        PrincipalId=user.UserId,
        TargetId=target.account,
        TargetType="AWS_ACCOUNT",
    )

    log.info("created account assignment", result=acc_assignment)

    # poll the assignment api to see if the assignment was successful
    res = check_account_assignment_status(
        p, acc_assignment["AccountAssignmentCreationStatus"]["RequestId"]
    )

    log.info("checked account assignment status", result=res)

    # log the success or failure of the grant
    if res["AccountAssignmentCreationStatus"]["Status"] != "SUCCEEDED":
        raise Exception(
            f'Error creating account assigment: {res["AccountAssignmentCreationStatus"]["FailureReason"]}'
        )


@access.revoke()
def revoke(p: Provider, subject: str, target: AccountTarget):
    # find the user id from the email address subject
    user = p.get_user(subject)

    acc_assignment = p.sso_client.delete_account_assignment(
        InstanceArn=p.sso_instance_arn.get(),
        PermissionSetArn=target.permission_set,
        PrincipalType="USER",
        PrincipalId=user.UserId,
        TargetId=target.account,
        TargetType="AWS_ACCOUNT",
    )

    log.info("deleted account assignment", result=acc_assignment)

    # poll the assignment api to see if the assignment was successful
    res = check_account_deletion_status(
        p, acc_assignment["AccountAssignmentDeletionStatus"]["RequestId"]
    )

    log.info("checked account assignment status", result=res)

    # log the success or failure of the grant
    if res["AccountAssignmentDeletionStatus"]["Status"] != "SUCCEEDED":
        raise Exception(
            f'Error deleting account assigment: {res["AccountAssignmentDeletionStatus"]["FailureReason"]}'
        )


@provider.config_validator(name="Verify AWS organization access")
def can_describe_organization(p: Provider, diagnostics: diagnostics.Logs) -> None:
    res = p.org_client.describe_organization()

    if len(res["Organization"]) > 0:
        diagnostics.info("Successfully described org")


@provider.config_validator(name="List Users")
def can_list_users(p: Provider, diagnostics: diagnostics.Logs) -> None:
    res = p.idstore_client.list_users(IdentityStoreId=p.sso_identity_store_id.get())

    user_count = len(res["Users"])
    diagnostics.info(f"found {user_count} users")


def next_token(page: typing.Optional[str]) -> dict:
    """
    returns a type-safe next token for use with boto3
    """
    if page is None:
        return {}  # type: ignore
    return {"NextToken": page}


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
                tasks.call(ListAccountsForOU(parent_id=id, ou_path=id))
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
    ou_path: str = ""
    parent_id: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.org_client.list_children(
            ParentId=self.parent_id, ChildType="ACCOUNT", **next_token(self.page)
        )
        for child in res["Children"]:
            if child.get("Type") == "ACCOUNT":
                tasks.call(
                    DescribeAccount(
                        account_id=child.get("Id"),
                        org_unit=self.parent_id,
                        ou_path=self.ou_path,
                    ),
                )
            if child.get("Type") == "ORGANIZATIONAL_UNIT":
                tasks.call(
                    ListAccountsForOU(
                        parent_id=child.get("Id"),
                        ou_path="/".join(self.ou_path, child.get("Id")),
                    )
                )
        if res.get("NextToken") is not None:
            # iterate through pages
            self.page = res["NextToken"]
            tasks.call(self)


class DescribeAccount(tasks.Task):
    account_id: str
    org_unit: str
    ou_path: str

    def run(self, p):
        res = p.org_client.describe_account(AccountId=self.account_id)
        name = res["Account"].get("Name")
        acc = Account(
            id=self.account_id,
            parent_org_unit=self.org_unit,
            name=name,
            org_unit_path=self.ou_path,
        )

        # find the tags associated with the account
        paginator = p.org_client.get_paginator("list_tags_for_resource")
        page_iterator = paginator.paginate(ResourceId=self.account_id)
        for page in page_iterator:
            tags = page["Tags"]
            for t in tags:
                acc.tags[t["Key"]] = t["Value"]

        resources.register(acc)


@resources.loader
def fetch_org_structure(p: Provider):
    list_roots = p.org_client.list_roots()
    root = list_roots["Roots"][0]
    root_id = root.get("Id")
    if root_id is None:
        raise Exception("could not find org root")
    resources.register(OrgUnit(id=root_id, name="Root"))
    tasks.call(ListChildrenForOU(parent_id=root_id))
    tasks.call(ListAccountsForOU(parent_id=root_id))


class ListPermissionSets(tasks.Task):
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.sso_client.list_permission_sets(
            InstanceArn=p.sso_instance_arn.get(), **next_token(self.page)
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
            InstanceArn=p.sso_instance_arn.get(),
            PermissionSetArn=self.permission_set_arn,
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
            InstanceArn=p.sso_instance_arn.get(),
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
            InstanceArn=p.sso_instance_arn.get(),
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
            InstanceArn=p.sso_instance_arn.get(),
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


@resources.loader
def fetch_permission_sets(p: Provider):
    tasks.call(ListPermissionSets())


class ListUsers(tasks.Task):
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.idstore_client.list_users(
            IdentityStoreId=p.sso_identity_store_id.get(), **next_token(self.page)
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
            if primary_email is not None and primary_email != "":
                resources.register(
                    User(id=u["UserId"], email=primary_email, name=primary_email)
                )

        if res.get("NextToken") is not None:
            self.page = res.get("NextToken")
            tasks.call(self)


class ListGroups(tasks.Task):
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        res = p.idstore_client.list_groups(
            IdentityStoreId=p.sso_identity_store_id.get(), **next_token(self.page)
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
            IdentityStoreId=p.sso_identity_store_id.get(),
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


@resources.loader
def fetch_users(p: Provider):
    tasks.call(ListUsers())


@resources.loader
def fetch_groups(p: Provider):
    tasks.call(ListGroups())


# got implementation from this stackoverflow https://stackoverflow.com/questions/44171849/aws-boto3-assumerole-example-which-includes-role-usage
def get_boto3_session(role_arn=None):
    session = boto3.Session()
    if not role_arn or role_arn == "":
        return session

    fetcher = AssumeRoleCredentialFetcher(
        client_creator=_get_client_creator(session),
        source_credentials=session.get_credentials(),
        role_arn=role_arn,
    )
    botocore_session = botocore.session.Session()
    botocore_session._credentials = DeferredRefreshableCredentials(
        method="assume-role", refresh_using=fetcher.fetch_credentials
    )

    return boto3.Session(botocore_session=botocore_session)


def _get_client_creator(session):
    def client_creator(service_name, **kwargs):
        return session.client(service_name, **kwargs)

    return client_creator
