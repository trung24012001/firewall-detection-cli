## Illustrative Example of the Resolve Algorithm

Firewall rules are expected in the following format: 
- priority. <protocol, source IP, source port, destination IP, destination port, actions>
```
1. <TCP, 129.110.96.117, *, *, 80, REJECT>
2. <TCP, 129.110.96.*, *, *, 80, ACCEPT>
3. <TCP, *, *, 129.110.96.80, 80, ACCEPT>
4. <TCP, {129.110.96.*, 1.2.3.4}, *, 129.110.96.80, 80, REJECT>
5. <TCP, 129.110.96.80, 22, *, *, REJECT>
6. <TCP, 129.110.96.117, *, {129.110.96.80, 112.134.30.54}, {22-3000}, REJECT>
7. <UDP, 129.110.96.117, *, 129.110.96.*, 22, REJECT>
8. <{UDP, TCP}, 129.110.96.117, *, 129.110.96.80, 22, REJECT>
9. <UDP, 129.110.96.117, *, 129.110.96.117, 22, ACCEPT>
10. <*, 129.110.96.117, *, 129.110.96.117, 22, REJECT>
11. <UDP, *, *, *, *, REJECT>
```