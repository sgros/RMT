RMT - Risk Management Tool
==========================

This is a tool for information security risk management. It
is still in the early ages, and thus very dynamic. There are
lot of different technologies that could and should be used,
but at the moment everything is a homegrown. So, big changes
are ahead, so stay tuned.

At the moment this is only risk assessment tool in the early
stages of development. There is command line tool,
RiskManagement.py, and a GUI tool RiskManagementUI.py. Both
of them are for viewing only. Editing must be done in the
command line.

To run it, after you downloaded source, go to the main
directory and type the following command:

./src/RiskManagementUI.py ./data/base

This command starts GUI for viewing risk management data stored
in the directory ./data/base. There is also another directory,
./daba/banks that holds data specific for the banking industry.
Finally, to start a command line version, use:

./src/RiskManagement.py ./data/base

Don't expect much for now. :)

