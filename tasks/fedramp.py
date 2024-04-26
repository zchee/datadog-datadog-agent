"""
Invoke entrypoint, import here all the tasks we want to make available
"""

# import os

from invoke import task
from invoke.exceptions import Exit

from tasks.libs.owners.parsing import read_owners

CODEOWNERS_FILE_PATH = ".github/CODEOWNERS"


def is_team_owner(file: str, team: str) -> bool:
    codeowners = read_owners(CODEOWNERS_FILE_PATH)
    team = team.lower()
    file_owners = codeowners.of(file)
    file_owners = [(x[0], x[1].lower()) for x in file_owners]
    return ("TEAM", team) in file_owners


@task
def check(_):
    """
    Check remaining ASC owned files
    """
    remained = []

    # Check comp/README.md
    with open("ASC_OWNED_CODE.txt", "r") as file:
        for line in file:
            with open(line.strip(), "r") as f:
                content = f.read()
                if content.startswith("// FEDRAMP REVIEW TODO"):
                    remained.append(line.strip())

    if remained:
        print("Some ASC owned files need FEDRAMP review")
        for file in remained:
            print(file)
        raise Exit(code=1)
