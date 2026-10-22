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
