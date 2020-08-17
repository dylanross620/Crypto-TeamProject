Made by Ryan Prashad, Leith Reardon, and Dylan Ross.
This project requires Python 3.8+ in order to run.

In order to run this project, first run 'bank.py' to initialize the server, then run 'atm.py' while the bank is still running.

The bank currently has 3 users. For the blackhat team, we created the user "Hacker" with the password "crypto".

Our project makes a few assumptions. First of all, all files in the local_storage directory are meant to be private (i.e. the blackhats cannot look at or modify
these files as part of an attack). These files are ones that would realistically be on the local storage of the atm and/or the bank server, and as such would not
be visible over the network. We also made the assumption that all atms have the bank's public key locally, which is very similar to real systems such as the secure
boot chain on the Nintendo Switch console. Finally, we assumed that the bank has a repository of all atm public keys, which is how ssh services often do user
authentication.

Our project only handles one atm per time running the bank program. As such, the bank will need to be restarted between atm instances. For use in a real-world situation,
our code could easily be multithreaded where our current project is a thread that is spawned for each attempted connection made to the bank.
