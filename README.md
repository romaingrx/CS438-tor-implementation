# Tor on Peerster

How to?
---

To visualize the proxy request, open the page `ourgui/gui.html`

In order to run all the nodes (proxies and relays), you just need to call `run.sh` with these arguments
```bash
./run.sh {num_relays} {num_proxies} 
    num_relays: The number of relays in the whole network
    num_proxies: The number of proxies capable of doing a request through the network
````

Then you can stop all the nodes with the command
```bash
./stop.sh
```
