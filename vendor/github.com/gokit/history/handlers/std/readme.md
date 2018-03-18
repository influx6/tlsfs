Std Handler
--------------
Exposes a handler method to write a simple format to a writer. The package-level variable `std.Std` logs to `stderr` file.


## Format

```bash
⡿ tcpServerClient.readLoop		Elapsed: 81.003µs	Tags: ["mtcp-server"]
 ⠙ Message: received data	Ts: 2018-03-01 10:50:18.161023 +0000 UTC
   fnCallAt: mtcp.(*tcpServerClient).readLoop:616	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/mtcp/network.go	
   fnCallIn: runtime.goexit:2337	/Users/darkvoid/devlabs/local/src/go/src/runtime/asm_amd64.s	

	⠙ KV: "addr"	"localhost:65350"
	⠙ KV: "client-id"	"b40f130f-ddbb-4407-8180-55e229c4831a"
	⠙ KV: "data"	"MNET:RINFO {\"Cluster\":false,\"ServerNode\":false,\"ID\":\"18bf2c74-62f1-4143-8594-88b88bca987a\",\"ServerAddr\":\"127.0.0.1:65350\",\"MaxBuffer\":65536,\"MinBuffer\":512,\"ClusterNodes\":null,\"Meta\":null}"
	⠙ KV: "localAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "network-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "remoteAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65352, Zone:""}
	⠙ KV: "server-addr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "server-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "serverName"	"localhost"

⡿ tcpServerClient.handshake		Elapsed: 1.09339ms	Tags: ["mtcp-server"]
 ⠙ Message: handshake completed	Ts: 2018-03-01 10:50:18.161587 +0000 UTC
   fnCallAt: mtcp.(*tcpServerClient).handshake:476	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/mtcp/network.go	
   fnCallIn: mtcp.(*TCPNetwork).addClient:977	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/mtcp/network.go	

	⠙ KV: "addr"	"localhost:65350"
	⠙ KV: "client-id"	"b40f130f-ddbb-4407-8180-55e229c4831a"
	⠙ KV: "localAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "network-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "remoteAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65352, Zone:""}
	⠙ KV: "server-addr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "server-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "serverName"	"localhost"

⡿ tcpServerClient.readLoop		Elapsed: 28.513µs	Tags: ["mtcp-server"]
 ⠙ Message: received data	Ts: 2018-03-01 10:50:18.161784 +0000 UTC
   fnCallAt: mtcp.(*tcpServerClient).readLoop:616	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/mtcp/network.go	
   fnCallIn: runtime.goexit:2337	/Users/darkvoid/devlabs/local/src/go/src/runtime/asm_amd64.s	

	⠙ KV: "addr"	"localhost:65350"
	⠙ KV: "client-id"	"b40f130f-ddbb-4407-8180-55e229c4831a"
	⠙ KV: "data"	"OBS {\"addr\":\"tcp://190.23.232.12:65351\",\"secret\":\"sygar-slicker\",\"region\":\"africa-west\",\"protocol\":\"\",\"service\":\"surga\",\"meta\":null,\"server\":null,\"interests\":null}"
	⠙ KV: "localAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "network-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "remoteAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65352, Zone:""}
	⠙ KV: "server-addr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "server-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "serverName"	"localhost"

⡿ tcpServerClient.readLoop		Elapsed: 20.563µs	Tags: ["mtcp-server"]
 ⠙ Message: read header error	Err: "read tcp 127.0.0.1:65350->127.0.0.1:65352: use of closed network connection"	Ts: 2018-03-01 10:50:18.265246 +0000 UTC
   fnCallAt: mtcp.(*tcpServerClient).readLoop:601	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/mtcp/network.go	
   fnCallIn: runtime.goexit:2337	/Users/darkvoid/devlabs/local/src/go/src/runtime/asm_amd64.s	

	⠙ KV: "addr"	"localhost:65350"
	⠙ KV: "client-id"	"b40f130f-ddbb-4407-8180-55e229c4831a"
	⠙ KV: "localAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "network-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "remoteAddr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65352, Zone:""}
	⠙ KV: "server-addr"	&net.TCPAddr{IP:net.IP{0x7f, 0x0, 0x0, 0x1}, Port:65350, Zone:""}
	⠙ KV: "server-id"	"b812e63f-97a7-4062-a147-dbd2dfafa08d"
	⠙ KV: "serverName"	"localhost"

⡿ node.Serve		Elapsed: 105.460816ms	Tags: ["discovery.Node"]
 ⠙ Message: handshake completed	Ts: 2018-03-01 10:50:18.265095 +0000 UTC
   fnCallAt: discovery.(*Node).Serve:163	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/discovery/discovery.go	
   fnCallIn: discovery.(*Service).serveClient:915	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/discovery/discovery.go	

 ⠙ Message: node registered	Ts: 2018-03-01 10:50:18.265181 +0000 UTC
   fnCallAt: discovery.(*Node).Serve:168	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/discovery/discovery.go	
   fnCallIn: discovery.(*Service).serveClient:915	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/discovery/discovery.go	

	⠙ KV: "node.id"	"09bc38b1-7c21-4ab6-9012-a668249f2eed"

⡿ clientNetwork.readLoop		Elapsed: 106.267371ms	Tags: ["mtcp-client"]
 ⠙ Message: read header error	Err: "EOF"	Ts: 2018-03-01 10:50:18.265456 +0000 UTC
   fnCallAt: mtcp.(*clientNetwork).readLoop:497	/Users/darkvoid/devlabs/src/github.com/influx6/mnet/mtcp/client.go	
   fnCallIn: runtime.goexit:2337	/Users/darkvoid/devlabs/local/src/go/src/runtime/asm_amd64.s	

	⠙ KV: "id"	"18bf2c74-62f1-4143-8594-88b88bca987a"

```