# QKD-P1

> [!note] Problem Statement
> The long-term security of sensitive patient health records is threatened by the future development of quantum computers capable of breaking capable of breaking current cryptographic standards. Quantum Key Distribution (QKD) offers a solution, but its practical feasibility and robustness for healthcare applications remain unproven.
>
> This project will investigate the viability of implementing QKD to secure the exchange of health data, by developing a simulated application to model the transmission of patient data between two hospital nodes.
>
> > [!info] To guide this work the following research questions are posed:
> > - Which existing QKD standards are most relevant and applicable to a healhcare data transfer system?
> > - How can a simulated application be designed to model secure transmission s
> > - How does the system perform under different network and key-management conditions?
> > - What are the key challenges, vulnerabilities, and integration barriers in applying QKD to healthcare research data exchange?

## Quantum Key Distribution (QKD)

Quantum Key Distribution (QKD) is a technology which allows two or more parties to
exchange encryption keys with guaranteed secrecy using quantum physics- that is, it is
impossible for an attacker to intercept and/or alter a key as it is exchanged. This emerging
technology has great potential for ensuring confidential data stays secret- however, there
are also many difficulties, especially regarding scalability and useability within different
domains. The goal of this project is to determine what potential sectors or scenarios could
benefit from QKD.

### Basic Preliminary Proposal

Look into a possible “type” of traffic/a specific use case.
Examples/possible use cases:

- Data center traffic
  - Data needs to be sent from datacenter A to datacenter B
- Patient records
  - Hospital A has records that hospital B needs
- Banking/financial market infrastructure/money transfer
  - Person A needs to transfer money to person B
- Energy/utility company
  - An energy company operates a lot of different devices remotely
Make an app that creates/handles that traffic using the QKD ETSI 014 network stack
- Discuss challenges in design, implementation, future development and what possible security pitfalls may arise regarding confidentiality, integrity and availability of the data
  - Emphasis should be how they fit the use case
  - i.e. if we are talking healthcare, is the system stable enough for exchanging patient records

## The Project
