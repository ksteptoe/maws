"""
    Example conftest.py for maws
    Read more about conftest.py under:
    - https://docs.pytest.org/en/stable/fixture.html
    - https://docs.pytest.org/en/stable/writing_plugins.html
"""
from collections import namedtuple
from os import chdir
from pathlib import Path

from pytest_cases import fixture, parametrize_with_cases

TestData = namedtuple("TestData", ["input_files", "expected_files", "produced_files"])


def case_Dec21():
    return TestData(
        ("Kevin_Steptoe_Expense_Report_December_2021.csv",),
        ("Kevin_Steptoe_Expense_Report_December_2021_GOLD.xlsx",),
        ("Kevin_Steptoe_Expense_Report_December_2021.xlsx",),
    )


def case_june20():
    return TestData(
        ("Kevin_Steptoe_Expense_Report_June_2020.csv",),
        ("Kevin_Steptoe_Expense_Report_June_2020_GOLD.xlsx",),
        ("Kevin_Steptoe_Expense_Report_June_2020.xlsx",),
    )


def case_oct21():
    return TestData(
        ("Kevin_Steptoe_Expense_Report_October_2021.csv",),
        ("Kevin_Steptoe_Expense_Report_October_2021_GOLD.xlsx",),
        ("Kevin_Steptoe_Expense_Report_October_2021.xlsx",),
    )


def case_june20_oct21():
    return TestData(
        (
            "Kevin_Steptoe_Expense_Report_October_2021.csv",
            "Kevin_Steptoe_Expense_Report_June_2020.csv",
        ),
        (
            "Kevin_Steptoe_Expense_Report_October_2021_GOLD.xlsx",
            "Kevin_Steptoe_Expense_Report_June_2020_GOLD.xlsx",
        ),
        (
            "Kevin_Steptoe_Expense_Report_October_2021.xlsx",
            "Kevin_Steptoe_Expense_Report_June_2020.xlsx",
        ),
    )


@fixture
@parametrize_with_cases("td", cases=".")
def build_env(td, datadir_copy):
    for l_of_files in [td.input_files, td.expected_files]:
        for f in l_of_files:
            s_file = datadir_copy[f]
    datadir = Path(s_file.dirname)
    with (datadir) as f:
        chdir(f)
    yield td
