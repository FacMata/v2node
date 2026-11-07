package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wyx2685/v2node/internal/hostagent"
)

func init() {
	var directory, enrollmentFile string
	var once bool
	agent := &cobra.Command{Use: "agent", Short: "Independent managed host control process"}
	agent.PersistentFlags().StringVar(&directory, "state-dir", "/var/lib/v2node-agent", "Private agent identity directory")
	enroll := &cobra.Command{Use: "enroll", Args: cobra.NoArgs, Short: "Exchange an enrollment file for a private host identity", RunE: func(cmd *cobra.Command, _ []string) error {
		return hostagent.Enroll(cmd.Context(), directory, enrollmentFile, version)
	}}
	enroll.Flags().StringVar(&enrollmentFile, "enrollment-file", "", "Owner-only JSON enrollment file (never place secrets in arguments)")
	_ = enroll.MarkFlagRequired("enrollment-file")
	run := &cobra.Command{Use: "run", Args: cobra.NoArgs, Short: "Report status and execute authorized tasks for an explicitly prepared installation", RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return hostagent.Run(ctx, directory, version, once)
	}}
	run.Flags().BoolVar(&once, "once", false, "Send exactly one observation and exit")
	agent.AddCommand(enroll, run)
	var binary, key, output, releaseVersion, commit, minimum string
	var sequence int64
	sign := &cobra.Command{Use: "sign-release", Args: cobra.NoArgs, Short: "Sign a release manifest offline (no publication)", RunE: func(_ *cobra.Command, _ []string) error {
		return hostagent.SignRelease(binary, key, output, releaseVersion, commit, minimum, sequence)
	}}
	sign.Flags().StringVar(&binary, "binary", "", "Linux amd64 binary")
	sign.Flags().StringVar(&key, "key-file", "", "Private signing-key file")
	sign.Flags().StringVar(&output, "manifest", "", "Manifest output path")
	sign.Flags().StringVar(&releaseVersion, "release-version", "", "Fixed release tag")
	sign.Flags().StringVar(&commit, "commit", "", "Source commit")
	sign.Flags().StringVar(&minimum, "min-agent-version", "", "Minimum compatible agent version")
	sign.Flags().Int64Var(&sequence, "sequence", 0, "Monotonic release sequence")
	for _, name := range []string{"binary", "key-file", "manifest", "release-version", "commit", "min-agent-version", "sequence"} {
		_ = sign.MarkFlagRequired(name)
	}
	agent.AddCommand(sign)
	var privateOutput, publicOutput string
	keygen := &cobra.Command{Use: "signing-keygen", Args: cobra.NoArgs, Short: "Create an Ed25519 release keypair in new files (never print the private key)", RunE: func(_ *cobra.Command, _ []string) error {
		return hostagent.GenerateSigningKey(privateOutput, publicOutput)
	}}
	keygen.Flags().StringVar(&privateOutput, "private-key-file", "", "New private key file")
	keygen.Flags().StringVar(&publicOutput, "public-key-file", "", "New public key file")
	_ = keygen.MarkFlagRequired("private-key-file")
	_ = keygen.MarkFlagRequired("public-key-file")
	agent.AddCommand(keygen)
	var layout, managedDir, bridge, manifest, signature, pubkey, serverConfig string
	prepare := &cobra.Command{Use: "prepare", Args: cobra.NoArgs, Short: "Prepare signed bridge files and systemd units; do not activate services", RunE: func(_ *cobra.Command, _ []string) error {
		return hostagent.Prepare(directory, layout, managedDir, bridge, manifest, signature, pubkey, serverConfig)
	}}
	prepare.Flags().StringVar(&layout, "layout", "/usr/local/lib/v2node-managed", "Release layout")
	prepare.Flags().StringVar(&managedDir, "managed-dir", "/var/lib/v2node-managed", "Shared maintenance state")
	prepare.Flags().StringVar(&bridge, "binary", "", "Signed bridge binary")
	prepare.Flags().StringVar(&manifest, "manifest", "", "Signed manifest")
	prepare.Flags().StringVar(&signature, "signature", "", "Detached signature")
	prepare.Flags().StringVar(&pubkey, "public-key-file", "", "Pinned release public key")
	prepare.Flags().StringVar(&serverConfig, "config", "/etc/v2node/config.json", "Existing server configuration")
	for _, name := range []string{"binary", "manifest", "signature", "public-key-file"} {
		_ = prepare.MarkFlagRequired(name)
	}
	agent.AddCommand(prepare)
	command.AddCommand(agent)
}
