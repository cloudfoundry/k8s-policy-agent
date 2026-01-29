package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"code.cloudfoundry.org/k8s-policy-agent/internal/agent"
	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/reconciler"

	"code.cloudfoundry.org/lager/v3"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	ctx := signalContext()

	logger := lager.NewLogger("policy-agent")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG))
	log.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(os.Stdout)))

	cfg := config.Load()
	logger.Info("loaded configuration", lager.Data{
		"policy_server_url": cfg.PolicyServerURL,
		"namespace":         cfg.Namespace,
		"poll_interval":     cfg.PollInterval,
	})

	runtimeManager, err := agent.NewRuntimeManager(ctx, logger, cfg)
	if err != nil {
		logger.Fatal("failed to initialize client manager", err)
	}

	policyClient, err := agent.NewPolicyServerClient(logger, cfg)
	if err != nil {
		logger.Fatal("failed to initialize policy server client", err)
	}

	networkPolicyReconciler := reconciler.New(runtimeManager.KubernetesClient(), cfg, logger)
	policyAgent := agent.New(runtimeManager.KubernetesClient(), policyClient, networkPolicyReconciler, cfg, logger)

	if err := runtimeManager.Add(policyAgent); err != nil {
		logger.Fatal("failed to add policy agent to manager", err)
	}

	if err := runtimeManager.Start(ctx); err != nil {
		logger.Fatal("failed to start client manager", err)
	}
}

func signalContext() context.Context {
	shutdownHandler := make(chan os.Signal, 1)

	ctx, cancel := context.WithCancel(context.Background())
	signal.Notify(shutdownHandler, []os.Signal{syscall.SIGINT, syscall.SIGTERM}...)
	go func() {
		<-shutdownHandler
		cancel()
	}()

	return ctx
}
