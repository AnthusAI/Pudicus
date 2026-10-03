Feature: Zero-config out-of-the-box sensitive-data detection
  As a developer installing Pudicus
  We want the shipped default config to catch sensitive data immediately
  So that a fresh install protects commits without any custom configuration

  Scenario: Default config blocks a staged synthetic API key
    Given a repository installed with pudicus defaults
    And a staged file containing a synthetic OpenAI-style key
    When I commit the staged files
    Then the commit should be blocked

  Scenario: Default config allows a clean staged commit
    Given a repository installed with pudicus defaults
    And a staged file containing harmless source code
    When I commit the staged files
    Then the commit should be allowed
    And the committed message should contain a clean inspection result

  Scenario: Public wallet addresses and hashes are not flagged
    Given a repository installed with pudicus defaults
    And a staged file containing public wallet addresses and digests
    When I commit the staged files
    Then the commit should be allowed