package impl

import (
	"fmt"
	"golang.org/x/xerrors"
	"strings"
)

func (n *node) AddNodeToDirectory(name string, info NodeInfo) error {
	if !n.directory.Add(name, info) {
		return xerrors.Errorf("Node %s already in the directory", name)
	}
	return nil
}

func (n *node) AddNodesToDirectory(nodesInfo map[string]NodeInfo) error {
	var errors []string
	for name, info := range nodesInfo {
		if err := n.AddNodeToDirectory(name, info); err != nil {
			errors = append(errors, fmt.Sprintf("%v", err))
		}
	}

	return xerrors.Errorf("%s", strings.Join(errors, "\n"))
}

// CreateCircuit will construct and exchange keys with the nodes
func (n *node) CreateCircuit(uid string, nodes []string) error {
	panic("implement me")
}

func (n *node) HandleExchangeKey(uid string, from string, publicKey []byte) error {
	panic("implement me")
}

