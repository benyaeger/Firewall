# DOS and DDOS Firewall
## A firewall that detects and blocks DOS and DDOS attacks.
The firewall examines the network's regular traffic received at the host, and looks for common DOS and DDOS attack patterns.

The program uses the WinDivert library to intercept packets received at the host's NIC and evaluate their fields and data.

The DOS and DDOS attack pattern detection operation relys on time intervals between packets and packets' source addresses.
