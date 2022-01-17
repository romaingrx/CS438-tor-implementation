// Package main implements a simple CLI that can start the http proxy.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	urfave "github.com/urfave/cli/v2"
	"go.dedis.ch/cs438/gui/httpnode"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/registry/standard"

	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/storage/file"
	"go.dedis.ch/cs438/storage/inmemory"

	"go.dedis.ch/cs438/transport/udp"
	"golang.org/x/xerrors"
)

const peerAddrMsg = "peer addr: '%s'"

var peerFactory = impl.NewPeer

var (
	// defaultLevel can be changed to set the desired level of the logger
	defaultLevel = zerolog.InfoLevel

	// logout is the logger configuration
	logout = zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}

	log zerolog.Logger
)

func init() {
	if os.Getenv("HTTPLOG") == "warn" {
		defaultLevel = zerolog.WarnLevel
	}

	if os.Getenv("HTTPLOG") == "no" {
		defaultLevel = zerolog.Disabled
	}

	log = zerolog.New(logout).
		Level(defaultLevel).
		With().Timestamp().Logger().
		With().Caller().Logger().
		With().Str("role", "cli node").Logger()

}

func main() {
	app := &urfave.App{
		Name:  "Node controller",
		Usage: "Please use the start command",

		Commands: []*urfave.Command{
			{
				Name:  "start",
				Usage: "starts the node and proxy",
				Flags: []urfave.Flag{
					&urfave.StringFlag{
						Name:  "proxyaddr",
						Usage: "addr of the proxy",
						Value: "127.0.0.1:0",
					},
					&urfave.StringFlag{
						Name:  "nodeaddr",
						Usage: "addr of the node",
						Value: "127.0.0.1:0",
					},
					&urfave.DurationFlag{
						Name:  "antientropy",
						Usage: "Antientropy interval",
						// 0 means the antientropy is not activated
						Value: 0,
					},
					&urfave.DurationFlag{
						Name:  "heartbeat",
						Usage: "Heartbeat interval",
						// 0 means the heartbeat is not activated
						Value: 0,
					},
					&urfave.DurationFlag{
						Name:  "acktimeout",
						Usage: "Timeout of ack message",
						// this is considered as a reasonable timeout value for
						// a small system.
						Value: time.Second * 3,
					},
					&urfave.Float64Flag{
						Name:  "continuemongering",
						Usage: "probability to continue mongering",
						// by default there is a 50% chance to continue
						// mongering.
						Value: 0.5,
					},
					&urfave.StringFlag{
						Name:  "storagefolder",
						Usage: "folder that will store peer's data. If not set will use in-memory storage",
						Value: "",
					},
					&urfave.UintFlag{
						Name:  "chunksize",
						Usage: "Size of chunks, in bytes",
						Value: 8192,
					},
					&urfave.DurationFlag{
						Name:  "backoffinitial",
						Usage: "Initial time for the backoff strategy",
						Value: time.Second * 2,
					},
					&urfave.UintFlag{
						Name:  "backofffactor",
						Usage: "Factor value for the backoff strategy",
						Value: 2,
					},
					&urfave.UintFlag{
						Name:  "backoffretry",
						Usage: "Retry value for the backoff strategy",
						Value: 5,
					},
					&urfave.UintFlag{
						Name:  "totalpeers",
						Usage: "Total number of peers (needed for Paxos)",
						Value: 1,
					},
					&urfave.UintFlag{
						Name:  "paxosid",
						Usage: "The peer's paxos id. Must stat at 1. Can be 0 if total peers <= 1.",
						Value: 0,
					},
					&urfave.DurationFlag{
						Name:  "paxosproposerretry",
						Usage: "The timeout after which a paxos proposer retries",
						Value: time.Second * 5,
					},
					&urfave.StringFlag{
						Name:  "directoryfilename",
						Usage: "The filename containing all directory nodes",
						Value: "directory.txt",
					},
					&urfave.IntFlag{
						Name:  "minimumcircuits",
						Usage: "The minimum number of circuits that can be randomly chosen",
						Value: 3,
					},
					&urfave.IntFlag{
						Name:  "maximumcircuits",
						Usage: "The maximum number of circuits that can be randomly chosen",
						Value: 5,
					},
					&urfave.DurationFlag{
						Name:  "circuitupdateticker",
						Usage: "The timeout after which the circuits are going to be updated",
						Value: time.Second * 2,
					},
					&urfave.DurationFlag{
						Name:  "lastusedunvalid",
						Usage: "The timeout after which if the circuit is not used, it is deleted",
						Value: time.Minute * 2,
					},
					&urfave.BoolFlag{
						Name:  "proxy",
						Usage: "If this node is a proxy or a relay",
						Value: false,
					},
					&urfave.IntFlag{
						Name:  "messages",
						Usage: "number of messages to send",
						Value: 10,
					},
					&urfave.IntFlag{
						Name:  "parallel",
						Usage: "messages to send in parallel",
						Value: 5,
					},
				},
				Action: start,
			},
		},

		Action: func(c *urfave.Context) error {
			urfave.ShowAppHelpAndExit(c, 1)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
}

// start starts the http proxy. It will create a UDP socket.
func start(c *urfave.Context) error {
	proxyAddr := c.String("proxyaddr")
	nodeAddr := c.String("nodeaddr")

	trans := udp.NewUDP()

	sock, err := trans.CreateSocket(nodeAddr)
	if err != nil {
		return xerrors.Errorf("failed to create socket")
	}

	// this message is used by the binary node to get the peer address
	log.Info().Msgf(peerAddrMsg, sock.GetAddress())

	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("socketaddress_%d", os.Getpid()))

	err = ioutil.WriteFile(socketPath, []byte(sock.GetAddress()), os.ModePerm)
	if err != nil {
		return xerrors.Errorf("failed to write socket address file: %v", err)
	}

	var storage storage.Storage

	if c.String("storagefolder") == "" {
		storage = inmemory.NewPersistency()
	} else {
		storage, err = file.NewPersistency(c.String("storagefolder"))
		if err != nil {
			log.Fatal().Msgf("failed to create file storage: %v", err)
		}
	}
	totalPeers := c.Uint("totalpeers")
	paxosID := c.Uint("paxosid")

	if totalPeers > 1 && paxosID == 0 {
		return xerrors.Errorf("if total peers is set PaxosID must be set, too")
	}

	conf := peer.Configuration{
		Socket:          sock,
		MessageRegistry: standard.NewRegistry(),

		AntiEntropyInterval: c.Duration("antientropy"),
		HeartbeatInterval:   c.Duration("heartbeat"),
		AckTimeout:          c.Duration("acktimeout"),
		ContinueMongering:   c.Float64("continuemongering"),

		ChunkSize: c.Uint("chunksize"),
		BackoffDataRequest: peer.Backoff{
			Initial: c.Duration("backoffinitial"),
			Factor:  c.Uint("backofffactor"),
			Retry:   c.Uint("backoffretry"),
		},
		Storage: storage,

		TotalPeers: totalPeers,
		PaxosThreshold: func(u uint) int {
			return int(u/2 + 1)
		},
		PaxosID:            paxosID,
		PaxosProposerRetry: c.Duration("paxosproposerretry"),

		DirectoryFilename:   c.String("directoryfilename"),
		MinimumCircuits:     c.Int("minimumcircuits"),
		MaximumCircuits:     c.Int("maximumcircuits"),
		CircuitUpdateTicker: c.Duration("circuitupdateticker"),
		LastUsedUnvalid:     c.Duration("lastusedunvalid"),

		MetricMessageRetry:    time.Second * 5,
		MetricMessageInterval: time.Second * 2,
		DataMessageRetry:      time.Second * 4,
		DataMessageTimeout:    time.Second * 60,
		CircuitSelectAlgo:     peer.CT_RTT,
	}

	node := peerFactory(conf)

	node.SetLoggerServer("http://localhost:9999/log")

	httpnode := httpnode.NewHTTPNode(node, conf)

	notify := make(chan os.Signal, 1)
	signal.Notify(notify,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	err = httpnode.StartAndListen(proxyAddr)
	if err != nil {
		return xerrors.Errorf("failed to start and listen: %v", err)
	}

	if c.Bool("proxy") {
		node.StartProxy()
		time.Sleep(5 * time.Second)
		node.StartProxyServer(":9000")
		// messages := c.Int("messages")
		// parallel := c.Int("parallel")

		// for i := 1; i <= messages; i += parallel {
		// 	var wg sync.WaitGroup
		// 	for j := i; j <= messages && j-i < parallel; j++ {
		// 		wg.Add(1)
		// 		go func(w *sync.WaitGroup) {
		// 			defer w.Done()
		// 			result, err := node.SendMessage("GET", "http://localhost:9999/", "", []byte(""))
		// 			if err != nil {
		// 				fmt.Printf("Error sending message %s", err.Error())
		// 			} else {
		// 				fmt.Printf("Message Response after %d microseconds with body %s\n", result.ReceivedTimeStamp.Sub(result.SentTimeStamp).Microseconds(), result.ResponseData)
		// 			}
		// 		}(&wg)
		// 	}
		// 	wg.Wait()
		// }

		// node.SendMetrics("http://localhost:9999/metrics")
	}

	time.Sleep(10 * time.Second)
	fmt.Println(node.StringCircuits())

	<-notify
	log.Info().Msg("closing...")

	os.RemoveAll(socketPath)

	err = httpnode.StopAndClose()
	if err != nil {
		return xerrors.Errorf("failed to close: %v", err)
	}

	sock.Close()

	return nil
}
