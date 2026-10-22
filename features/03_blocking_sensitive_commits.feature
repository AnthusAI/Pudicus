@gitleaks
Feature: Blocking sensitive commits
  As a developer who commits many times a day
  I want LeftBlock to stop a commit that carries sensitive data
  So that the material never enters local history, where it would travel with every push and clone

  With the local gate installed, every commit is inspected before Git creates
  it. The shipped rules apply with no configuration. A blocked commit leaves
  HEAD where it was, names the rule that fired and never repeats the value.
  Only the staged changes are inspected, and clean commits go through untouched.

  Scenario: A staged API key blocks the commit
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

  Scenario: A blocked commit names the rule but never shows the value
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then stderr contains "leftblock-openai-key"
    And the output does not reveal the synthetic value

  Scenario: A clean commit goes through
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    Then the commit succeeds

  Scenario: Only staged changes are inspected
    Given a repository with LeftBlock installed as a local check-only gate
    And the file "notes.txt" is committed
    And an unstaged change to "notes.txt" containing a synthetic personal email
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    Then the commit succeeds

  Scenario: A commit that mixes clean and sensitive files is blocked as a whole
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    And a staged file "settings.py" containing a synthetic AWS key pair
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
