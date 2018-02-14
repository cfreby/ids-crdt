# Managing an Intrusion Detection System with CRDTs
This program presents a method for the synchronisation of databases of an IDS distributed on different sites.

# Intrusion Detection Systems
With the growth of communication technologies in the past decades, security has become a crucial point for the design of a network architecture. To ensure availability, integrity and confidentiality of the system, the implementation of an Intrusion Detection System (IDS) can help with the prevention of attacks.

An IDS works in 3 steps :
- Network monitoring : traffic is analyzed and filtered to gather various information (protocole, packet content, source and destination...)
- Database construction : Patterns observed in previous attacks are stored in a signature database gathering a list of parameters, so they can be compared with the monitored traffic.
- Alert emission : when the system detects a pattern in the monitored traffic that matches the signature database, an alert is sent to the operator so that countermeasures can be applied.

# Convergence of the system
If your system is distributed on various sites, an attack will only be registered on the network where it was detected. To ensure that a new type of intrusion is correctly managed by the other sites, the nodes of your system must communicate updates to inform about the addition of new rules in the signature database.

But as the network can induce delays in such communications, various sites may receive updates in various orders, and the databases can't reach a convergence in these conditions. With this program, we suggest the use of a CRDT (Conflict-Free Replicated Data Type) that will transform every update as commutative operations, so that they can be treated in various orders while still reaching the same result on every site.

To learn more about CRDTs, please refer to my references at the end of this file.

# Description
This program presents a way to manage a Snort-like IDS with the help of CRDTs. It includes:
- snortRule.py : a class for the creation and manipulation of Snort-like rules,
- crdtSnort.py : a class for the constitution of the signature database,
- main.py : the main program where a first thread creates and transmits rules to be added in the database of each site, while a second thread waits for updates from other nodes and adds received rules to the local database.

Some methods randomize the order of reception of every update to bring disorder in the databases, and an algorithm will be applied to ensure the convergence of the system.

# REFERENCES
M. Shapiro and N. Preguiça, “Designing a commutative replicated data type”
Institut National de la Recherche en Informatique et Automatique, Rocquencourt, France, Rapport de recherche RR-6320, Oct. 2007.
Available: http://hal.inria.fr/inria-00177693/

Nuno Preguiça, Joan Manuel Marquès, Marc Shapiro, Mihai Leția. “A commutative replicated data type for cooperative editing”.
29th IEEE International Conference on Distributed Computing Systems (ICDCS 2009), Jun 2009, Canada.

B. Nédelec, P. Molli, A. Mostefaoui, E. Desmontils, "LSEQ: An adaptive structure for sequences in distributed collaborative editing"
Proc. 13th ACM Symp. Document Eng., pp. 37-46, Sep. 2013.

https://www.snort.org/
