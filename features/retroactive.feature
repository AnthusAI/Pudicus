Feature: Retroactive Commit Approval
  As a development team
  We want to retroactively approve unsigned commits without rewriting history
  So that we can pass the deploy gate when someone bypasses the local hook

  Scenario: A range of unsigned commits can be retroactively approved
    Given a configured pudicus installation with a mock successful scanner
    And a range of 2 unsigned commits
    When I run the pudicus approve command for those commits
    Then a new approval commit should be created
    And the verification should pass for the entire range

  Scenario: Retroactive approval fails if a scanner finds secrets and no human override is provided
    Given a configured pudicus installation with a mock failing scanner
    And an unsigned commit containing a secret
    When I run the pudicus approve command for that commit without a TTY
    Then the approval commit should not be created
    And the verification should fail
