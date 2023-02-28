from commonfate_provider import resources
from provider.resources import OrgUnit, Account
from provider.provider import OrgUnitGroup, TagGroup


def test_org_unit_group_works():
    resources.set_fixture(
        [
            OrgUnit(id="root"),
            Account(id="123456789012", org_unit="root"),
        ]
    )
    group = OrgUnitGroup()
    got = group.match("root")

    assert got == ["123456789012"]


def test_org_unit_group_nested_accounts():
    resources.set_fixture(
        [
            OrgUnit(id="root"),
            OrgUnit(id="nested", parent="root"),
            Account(id="123456789012", org_unit="nested"),
        ]
    )
    group = OrgUnitGroup()
    got = group.match("root")
    want = ["123456789012"]
    assert got == want


def test_org_unit_group_ignores_account_not_in_ou():
    resources.set_fixture(
        [
            OrgUnit(id="root"),
            OrgUnit(id="nested", parent="root"),
            Account(id="123456789012", org_unit="nested"),
            Account(id="ignored", org_unit="root"),
        ]
    )
    group = OrgUnitGroup()
    got = group.match("nested")
    want = ["123456789012"]
    assert got == want


def test_tag_group_works():
    resources.set_fixture(
        [
            Account(id="123456789012", tags={"my-tag": "true"}),
            Account(id="ignored", tags={"my-tag": "false"}),
            Account(id="also-ignored", tags={"something-else": "false"}),
        ]
    )
    group = TagGroup()
    got = group.match("my-tag=true")
    want = ["123456789012"]
    assert got == want


def test_tag_group_regex():
    resources.set_fixture(
        [
            Account(id="match-1", tags={"my-tag": "matches-match"}),
            Account(id="match-2", tags={"my-tag": "matches-metoo"}),
            Account(id="ignored", tags={"my-tag": "none"}),
            Account(id="also-ignored", tags={"something-else": "false"}),
        ]
    )
    group = TagGroup()
    got = group.match("my-tag=matches-.*")
    want = ["match-1", "match-2"]
    assert got == want
