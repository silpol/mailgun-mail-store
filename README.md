# mailgun-mail-store
small [Python](https://www.python.org/) script to implement [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface) service, which accepts web calls from [Mailgun](https://www.mailgun.com/), to store messages and optionally process them

this script launches as WSGI server, and waits for MailGun to execute web API call in order to pass message previously sent via their mail relay.

The script uses [Flask](https://en.wikipedia.org/wiki/Flask_(web_framework)) web framework to simplify development.

Testing uses pytest-flask as foundation.