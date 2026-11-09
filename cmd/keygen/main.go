// Command keygen provisions the key material for a deployment:
//   - one long-term identity key pair per node (Ed25519 and/or ML-DSA-65)
//   - the Groth16 proving/verifying keys for the Berkeley circuits
//
// Prototype only: the Groth16 setup is run locally by whoever runs keygen
// (a production system would use an MPC ceremony), and private keys are
// written to disk unencrypted.
//
//	go run ./cmd/keygen -n 4 -out keys
package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"secure-distributed-system/internal/cluster"
	"secure-distributed-system/internal/config"
	"secure-distributed-system/internal/handshake"
	"secure-distributed-system/internal/zkp"
)

func main() {
	n := flag.Int("n", 4, "number of nodes")
	out := flag.String("out", "keys", "output directory")
	noZKP := flag.Bool("no-zkp", false, "skip the Groth16 setup")
	flag.Parse()

	for _, suite := range []handshake.Suite{handshake.SuiteClassical, handshake.SuiteHybrid} {
		for i := 0; i < *n; i++ {
			s, err := cluster.GenerateIdentity(suite)
			if err != nil {
				log.Fatal(err)
			}
			if err := config.WriteIdentity(*out, uint32(i), suite, s); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Printf("wrote %d %s identities to %s\n", *n, suite.SignatureAlgorithm(), *out)
	}
	if *noZKP {
		return
	}
	p, err := zkp.Setup(*n)
	if err != nil {
		log.Fatal(err)
	}
	dir := filepath.Join(*out, "zkp")
	if err := p.Save(dir); err != nil {
		log.Fatal(err)
	}
	rc, ac := p.Constraints()
	fmt.Printf("Groth16 setup for n=%d in %v (range %d constraints, aggregate %d) -> %s\n", *n, p.SetupTime, rc, ac, dir)
}
