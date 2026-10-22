@gitleaks
Feature: Retroactive approval
  As a development team
  We want to approve unsigned commits after the fact without rewriting history
  So that we can pass the deploy gate when someone bypassed the local hook

  "leftblock approve" inspects the changes of each commit in a range and, when
  they are clean, adds one new empty commit carrying a receipt for each of them.
  Findings still need a human at a terminal; without one nothing is approved.

  Scenario: A range of unsigned commits is approved by one new commit
    Given a repository with LeftBlock installed in receipt mode
    And 2 unsigned commits
    When I run "leftblock approve HEAD~2..HEAD"
    Then the exit code is 0
    And the latest commit message contains "retroactive leftblock approval"
    When I run "leftblock verify HEAD~3..HEAD"
    Then the exit code is 0

  Scenario: Commits with sensitive data are not approved without a human
    Given a repository with LeftBlock installed in receipt mode
    And an unsigned commit containing a synthetic OpenAI key
    When I run "leftblock approve HEAD"
    Then the exit code is 1
    And HEAD has not moved
    And stderr contains "no interactive terminal"
    When I run "leftblock verify HEAD"
    Then the exit code is 1

  Scenario: The approval commit carries a receipt for every approved commit and one for itself
    Given a repository with LeftBlock installed in receipt mode
    And 2 unsigned commits
    When I run "leftblock approve HEAD~2..HEAD"
    Then the exit code is 0
    And the latest commit message carries 3 receipts
    And the latest commit is an empty commit directly on top of the previous HEAD

  Scenario: A single commit can be approved by naming it
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    When I run "leftblock approve HEAD"
    Then the exit code is 0
    And the latest commit message carries 2 receipts
    When I run "leftblock verify HEAD~1..HEAD"
    Then the exit code is 0

  Scenario: An empty range approves nothing and changes nothing
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    When I run "leftblock approve HEAD..HEAD"
    Then the exit code is 0
    And stderr contains "No commits found in range"
    And HEAD has not moved

  Scenario: A person at a terminal can approve old findings with the shared passphrase
    Given a repository with LeftBlock installed in receipt mode
    And an unsigned commit containing a synthetic OpenAI key
    When On an interactive terminal I run "leftblock approve HEAD" and enter the shared passphrase
    Then the exit code is 0
    And the latest commit message contains "Inspection-result: override:1-checkers"
    And the latest commit is an empty commit directly on top of the previous HEAD
    When I run "leftblock verify HEAD~1..HEAD"
    Then the exit code is 0

  Scenario: A wrong passphrase approves nothing
    Given a repository with LeftBlock installed in receipt mode
    And an unsigned commit containing a synthetic OpenAI key
    When On an interactive terminal I run "leftblock approve HEAD" and enter a wrong passphrase
    Then the exit code is 1
    And stderr contains "Incorrect passphrase"
    And HEAD has not moved

  Scenario: Approval is refused when the policy is missing
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    And there is no checker policy
    When I run "leftblock approve HEAD"
    Then the exit code is 1
    And stderr contains "Approval blocked"
    And stderr does not contain "Traceback"
    And HEAD has not moved

  Scenario: Approval is refused when a checker breaks, even for a person with the passphrase
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    And a checker script "crashing.py" containing:
      """
      import sys
      sys.exit(2)
      """
    And the checker policy is:
      """
      checkers:
        - name: crashing-scanner
          type: command
          command: $PYTHON $CHECKERS/crashing.py
      """
    When On an interactive terminal I run "leftblock approve HEAD" and enter the shared passphrase
    Then the exit code is 1
    And stderr contains "Approval blocked"
    And stderr does not contain "approval passphrase"
    And HEAD has not moved

  Scenario: Approval needs the shared secret
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    And the signing secret has been removed
    When I run "leftblock approve HEAD"
    Then the exit code is 1
    And stderr contains "Shared secret not found"
    And HEAD has not moved
