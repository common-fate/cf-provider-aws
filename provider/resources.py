import typing
from commonfate_provider import resources


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
