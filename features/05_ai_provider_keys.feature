@gitleaks
Feature: AI provider keys
  As a developer whose code calls AI provider APIs
  I want LeftBlock's shipped rules to recognise those providers' API keys
  So that a key pasted into code, config or a log never reaches a commit

  Keys with a distinctive prefix are caught anywhere. Keys without one are
  caught when assigned to a variable named after their provider. References
  to a key (environment lookups, placeholders) are not keys and pass.

  Scenario Outline: A pasted <provider> key is blocked even without a telling variable name
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "client.py" containing a synthetic <provider> key
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value
    And stderr contains "rotate"

    Examples:
      | provider     | rule                     |
      | OpenAI       | leftblock-openai-key     |
      | OpenAI admin | leftblock-openai-key     |
      | Anthropic    | leftblock-anthropic-key  |
      | Groq         | leftblock-groq-key       |
      | xAI          | leftblock-xai-key        |
      | Replicate    | leftblock-replicate-key  |
      | Together AI  | leftblock-together-key   |
      | OpenRouter   | leftblock-openrouter-key |
      | Fireworks    | leftblock-fireworks-key  |
      | Cerebras     | leftblock-cerebras-key   |
      | LangSmith    | leftblock-langsmith-key  |
      | ElevenLabs   | leftblock-elevenlabs-key |
      | Voyage AI    | leftblock-voyage-key     |
      | Pinecone     | leftblock-pinecone-key   |

  Scenario Outline: A <provider> key with no fixed prefix is blocked when assigned to a provider-named variable
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "settings.env" containing a synthetic <provider> key
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-ai-provider-key-assignment"
    And the output does not reveal the synthetic value

    Examples:
      | provider           |
      | Mistral            |
      | Cohere             |
      | Azure OpenAI       |
      | Deepgram           |
      | Together AI legacy |

  Scenario Outline: References to a key and placeholders are not blocked
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.txt" containing:
      """
      <line>
      """
    When I commit the staged files
    Then the commit succeeds

    Examples:
      | line                                   |
      | OPENAI_API_KEY=${OPENAI_API_KEY}       |
      | key = os.environ["ANTHROPIC_API_KEY"]  |
      | MISTRAL_API_KEY=your-key-here          |
      | GROQ_API_KEY=<your-api-key>            |
      | pip install scikit-learn  # sk-learn   |
