# What's Next

Open issues, ordered by priority:

{% for issue in query(status="open", sort="priority") %}
- [{{ issue.title }}]({{ issue.id }})
{% endfor %}

{% if count(status="open") == 0 %}
No open issues.
{% endif %}
