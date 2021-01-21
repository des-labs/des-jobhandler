<b>Name</b>: {{ firstname }} {{ lastname }}

<b>Email</b>: {{ email }}

<b>Topics</b>:
<ul>
{% for topic in topics -%}
<li>{{ topic }}</li>
{% endfor %}
</ul>
{% if othertopic -%}
Custom topic: {{ othertopic }}
{% endif %}

<b>Question</b>:
{{ message }}
