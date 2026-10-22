@gitleaks
Feature: What LeftBlock detects
  As a developer
  I want the shipped rules to recognise the kinds of material I must not commit
  So that a fresh install protects me without any configuration of my own

  The default ruleset covers personal data (emails, home-folder paths,
  identifiers), cloud and AI provider credentials and crypto wallet secrets.
  Public values that merely look similar, such as wallet addresses and
  digests, are left alone so the gate does not cry wolf.

  Scenario Outline: A staged <kind> is blocked by its rule
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "data.txt" containing a synthetic <kind>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value

    Examples:
      | kind                 | rule                       |
      | personal email       | leftblock-personal-email   |
      | home path            | leftblock-home-path-posix  |
      | Windows home path    | leftblock-home-path-windows |
      | session UUID         | leftblock-session-uuid     |
      | actor id             | leftblock-actor-id         |
      | AWS key pair         | aws-access-token           |
      | Ethereum private key | leftblock-eth-private-key  |
      | Bitcoin WIF key      | leftblock-wif-key          |
      | seed phrase          | leftblock-bip39-mnemonic   |

  Scenario: Public wallet addresses and digests are not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "addresses.txt" containing a synthetic public wallet address and digest
    When I commit the staged files
    Then the commit succeeds
