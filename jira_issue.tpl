
*ACTION ITEMS*
- ASSIGN this ticket if it is unassigned.
- SEND AN EMAIL TO *{{ email }}* AND *{{ emaillist }}* to reply to this ticket.
- CLOSE this ticket when resolved, copying any noteworthy info in the comments.

*Name*: {{ firstname }} {{ lastname }}

*Email*: {{ email }}

*Topics*:
{% for topic in topics -%}
- {{ topic }}
{% endfor %}
{% if othertopic -%}
Custom topic: {{ othertopic }}
{% endif %}

*Question*:
{{ message }}
