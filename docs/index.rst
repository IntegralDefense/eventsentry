Event Sentry
============

**Release:** |release|

Event Sentry automatically manages `ACE <https://github.com/IntegralDefense/ACE>`_ events and incidents and seeks to automate most of the common tasks performed by an intel analyst.

Major Features
--------------

* **Generates comprehensive wiki write-ups** to give analysts deep insight into the event.
* **Detects types of malware** using built-in and extendable detection modules.
* **Detects kill chain phase** by determining if a user clicked a link, submitted credentials, opened a malware sample, etc.
* **Extracts indicators** from e-mails, sandbox reports, and other artifacts.
* **Automatically uploads indicators** to SIP and creates appropriate relationships between them.
* **Maintains an event repository** containing copies of the ACE alerts and all their artifacts.
* **Creates a shareable intel package** containing a summary of the event including indicators, malware samples, and e-mail headers.

Compatibility
-------------

Event Sentry has been tested with the following configurations:

* Ubuntu 14.04 with Python 3.4
* Ubuntu 18.04 with Python 3.6

Required
^^^^^^^^

Event Sentry currently requires the following systems:

* `ACE <https://github.com/IntegralDefense/ACE>`_
* `SIP <https://github.com/IntegralDefense/SIP>`_
* `Confluence <https://www.atlassian.com/software/confluence>`_

Recommended
^^^^^^^^^^^

The following systems are technically optional, but they are highly recommended in order to realize the full potential of Event Sentry:

* `Splunk <https://www.splunk.com/>`_
* `Carbon Black <https://www.carbonblack.com/>`_

Installation
------------

Event Sentry provides an installer script to help get you up and running. It will ask where you would like it to be installed and will install all dependencies inside of a virtual environment.

.. code:: bash

    git clone https://github.com/IntegralDefense/eventsentry.git
    cd eventsentry
    ./installer.sh

After running the installer script, it will notify you of the various config files you must edit and how to run the provided unit tests to ensure things are configured properly.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   user-guide
   developer-guide
