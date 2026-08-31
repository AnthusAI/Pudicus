Feature: Commit Inspection Gate
  As a development team
  We want to run deterministic checks on staged code before committing
  So that secrets and other violations are caught early and a cryptographically signed receipt is generated

  Scenario: A clean commit automatically receives a signature
    Given a configured pudicus installation with a mock successful scanner
    And a staged file containing safe content
    When I run the pudicus hook
    Then the commit should be allowed
    And the commit message should contain an "Inspected-by" trailer
    And the commit message should contain an "Inspection-result: clean" trailer
    And the commit message should contain a valid "Inspection-sig" trailer

  Scenario: A commit with secrets is blocked if there is no human override
    Given a configured pudicus installation with a mock failing scanner
    And a staged file containing a secret
    When I run the pudicus hook without a TTY
    Then the commit should be blocked
    And the commit message should not contain an "Inspection-sig" trailer

  Scenario: Verifying a clean, signed commit
    Given a commit with a valid signature for its tree hash
    When I run the pudicus verify command on the commit
    Then the verification should pass

  Scenario: Verifying an unsigned commit fails
    Given a commit with no pudicus trailers
    When I run the pudicus verify command on the commit
    Then the verification should fail
