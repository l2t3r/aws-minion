======================
Command Line Interface
======================

Use the ``--help`` option to find out more about commands and subcommands:

.. code-block:: bash

    $ minion --help

.. Tip::

    All commands and subcommands can be abbreviated, i.e. the following lines are equivalent:

    .. code-block:: bash

        $ minion versions scale myapp 1.0 4
        $ minion ver sc myapp 1.0 4

The CLI supports multiple profiles (e.g. for different AWS accounts), use the global ``--profile`` option or the ``AWS_MINION_PROFILE`` environment variable to select a non-default profile:

.. code-block:: bash

    $ minion -p mynewprofile configure
    $ export AWS_MINION_PROFILE=mynewprofile
    $ minion applications


Bash Completion
===============

The programmable completion feature in Bash permits typing a partial command, then pressing the :kbd:`[Tab]` key to auto-complete the command sequence.
If multiple completions are possible, then :kbd:`[Tab]` lists them all.

To activate bash completion for the minion CLI, just run:

.. code-block:: bash

    $ eval "$(_MINION_COMPLETE=source minion)"

Put the eval line into your :file:`.bashrc`:

.. code-block:: bash

    $ echo 'eval "$(_MINION_COMPLETE=source minion)"' >> ~/.bashrc

